package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/docker/go-plugins-helpers/volume"
)

const socketAddress = "/run/docker/plugins/sshfs.sock"

type sshfsVolume struct {
	Password string
	Sshcmd   string
	Port     string

	Mountpoint  string
	connections int
}

type sshfsDriver struct {
	sync.RWMutex

	root      string
	statePath string
	volumes   map[string]*sshfsVolume
}

var debugf = func(format string, args ...interface{}) (int, error) { return 0, nil }

func newSshfsDriver(root string) (*sshfsDriver, error) {
	debugf("root=%s\n", root)

	d := &sshfsDriver{
		root:      filepath.Join(root, "volumes"),
		statePath: filepath.Join(root, "state", "sshfs-state.json"),
		volumes:   map[string]*sshfsVolume{},
	}

	data, err := ioutil.ReadFile(d.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("statePath not found: %s\n", d.statePath)
		} else {
			return nil, err
		}
	} else {
		if err := json.Unmarshal(data, &d.volumes); err != nil {
			return nil, err
		}
	}

	return d, nil
}

func (d *sshfsDriver) saveState() {
	data, err := json.Marshal(d.volumes)
	if err != nil {
		fmt.Printf("statePath=%s err=%v\n", d.statePath, err)
		return
	}

	if err := ioutil.WriteFile(d.statePath, data, 0644); err != nil {
		fmt.Printf("statePath=%s err=%v\n", d.statePath, err)
	}
}

func (d *sshfsDriver) Create(r volume.Request) volume.Response {
	debugJSON("create", r)

	d.Lock()
	defer d.Unlock()
	v := &sshfsVolume{}

	for key, val := range r.Options {
		switch key {
		case "sshcmd":
			v.Sshcmd = val
		case "password":
			v.Password = val
		case "port":
			v.Port = val
		default:
			return responseError(fmt.Sprintf("unknown option %q", val))
		}
	}

	if v.Sshcmd == "" {
		return responseError("'sshcmd' option required")
	}
	v.Mountpoint = filepath.Join(d.root, fmt.Sprintf("%x", md5.Sum([]byte(v.Sshcmd))))

	d.volumes[r.Name] = v

	d.saveState()

	return volume.Response{}
}

func (d *sshfsDriver) Remove(r volume.Request) volume.Response {
	debugJSON("remove", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	if v.connections != 0 {
		return responseError(fmt.Sprintf("volume %s is currently used by a container", r.Name))
	}
	if err := os.RemoveAll(v.Mountpoint); err != nil {
		return responseError(err.Error())
	}
	delete(d.volumes, r.Name)
	d.saveState()
	return volume.Response{}
}

var debugJSON = func(method string, x interface{}) {}

func (d *sshfsDriver) Path(r volume.Request) volume.Response {
	debugJSON("path", r)

	d.RLock()
	defer d.RUnlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	return volume.Response{Mountpoint: v.Mountpoint}
}

func (d *sshfsDriver) Mount(r volume.MountRequest) volume.Response {
	debugJSON("mount", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	if v.connections == 0 {
		fi, err := os.Lstat(v.Mountpoint)
		if os.IsNotExist(err) {
			if err := os.MkdirAll(v.Mountpoint, 0755); err != nil {
				return responseError(err.Error())
			}
		} else if err != nil {
			return responseError(err.Error())
		}

		if fi != nil && !fi.IsDir() {
			return responseError(fmt.Sprintf("%v already exist and it's not a directory", v.Mountpoint))
		}

		if err := d.mountVolume(v); err != nil {
			return responseError(err.Error())
		}
	}

	v.connections++

	return volume.Response{Mountpoint: v.Mountpoint}
}

func (d *sshfsDriver) Unmount(r volume.UnmountRequest) volume.Response {
	debugJSON("unmount", r)

	d.Lock()
	defer d.Unlock()
	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	v.connections--

	if v.connections <= 0 {
		if err := d.unmountVolume(v.Mountpoint); err != nil {
			return responseError(err.Error())
		}
		v.connections = 0
	}

	return volume.Response{}
}

func (d *sshfsDriver) Get(r volume.Request) volume.Response {
	debugJSON("get", r)

	d.Lock()
	defer d.Unlock()

	v, ok := d.volumes[r.Name]
	if !ok {
		return responseError(fmt.Sprintf("volume %s not found", r.Name))
	}

	return volume.Response{Volume: &volume.Volume{Name: r.Name, Mountpoint: v.Mountpoint}}
}

func (d *sshfsDriver) List(r volume.Request) volume.Response {
	debugJSON("list", r)

	d.Lock()
	defer d.Unlock()

	var vols []*volume.Volume
	for name, v := range d.volumes {
		vols = append(vols, &volume.Volume{Name: name, Mountpoint: v.Mountpoint})
	}
	return volume.Response{Volumes: vols}
}

func (d *sshfsDriver) Capabilities(r volume.Request) volume.Response {
	debugJSON("capabilities", r)

	return volume.Response{Capabilities: volume.Capability{Scope: "local"}}
}

func (d *sshfsDriver) mountVolume(v *sshfsVolume) error {
	cmd := fmt.Sprintf("sshfs -oStrictHostKeyChecking=no %s %s", v.Sshcmd, v.Mountpoint)
	if v.Port != "" {
		cmd = fmt.Sprintf("%s -p %s", cmd, v.Port)
	}
	if v.Password != "" {
		cmd = fmt.Sprintf("%s -o workaround=rename -o password_stdin", cmd)
	}
	debugf("cmd=%s\n", cmd)
	if v.Password != "" {
		cmd = fmt.Sprintf("echo %s | %s", v.Password, cmd)
	}
	return run(cmd)
}

func (d *sshfsDriver) unmountVolume(target string) error {
	cmd := fmt.Sprintf("umount %s", target)
	debugf("cmd=%s\n", cmd)
	return run(cmd)
}

func responseError(err string) volume.Response {
	fmt.Println(err)
	return volume.Response{Err: err}
}

func main() {
	debug := os.Getenv("DEBUG")
	if ok, _ := strconv.ParseBool(debug); ok {
		debugJSON = func(method string, x interface{}) {
			b, _ := json.Marshal(x)
			fmt.Printf("method=%s %s\n", method, b)
		}
		debugf = fmt.Printf
	}

	d, err := newSshfsDriver("/mnt")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	h := volume.NewHandler(d)
	fmt.Println("listening on", socketAddress)
	fmt.Println(h.ServeUnix("", socketAddress))
}

func run(cmd string) error {
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
	}
	return err
}
