# xdp-pktgen: xdp based packet generator

This is a simple xdp based packet generator.

## **Getting Started**

To get started, simply click the "Use this template" button on the GitHub repository page. This will create
a new repository in your account with the same files and structure as this template.

### Use docker

Run the following code to run the eBPF code from the cloud to your local machine in one line:

```console
$ sudo docker run --rm -it --privileged ghcr.io/eunomia-bpf/libbpf-template:latest
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
09:25:14 EXEC  sh               28142   1788    /bin/sh
09:25:14 EXEC  playerctl        28142   1788    /nix/store/vf3rsb7j3p7zzyjpb0a3axl8yq4z1sq5-playerctl-2.4.1/bin/playerctl
09:25:14 EXIT  playerctl        28142   1788    [1] (6ms)
09:25:15 EXEC  sh               28145   1788    /bin/sh
09:25:15 EXEC  playerctl        28145   1788    /nix/store/vf3rsb7j3p7zzyjpb0a3axl8yq4z1sq5-playerctl-2.4.1/bin/playerctl
09:25:15 EXIT  playerctl        28145   1788    [1] (6ms)
```

### Use Nix

Using [direnv](https://github.com/direnv/direnv) and nix, you can quickly access a dev shell with a complete development environment.

With direnv, you can automatically load the required dependencies when you enter the directory.
This way you don't have to worry about installing dependencies to break your other project development environment.

See how to install direnv and Nix:
- direnv: https://github.com/direnv/direnv/blob/master/docs/installation.md
- Nix: run
```
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Then use the following command to enable direnv support in this directory.

```sh
direnv allow
```

If you want use nix flake without direnv, simply run:

```sh
nix develop
```

## **Features**

This starter template includes the following features:

- A **`Makefile`** that allows you to build the project in one command
- A **`Dockerfile`** to create a containerized environment for your project
- A **`flake.nix`** to enter a dev shell with needed dependencies
- A GitHub action to automate your build and publish process
  and docker image
- All necessary dependencies for C development with libbpf

## **How to use**

### **1. Create a new repository using this template**

Click the "Use this template" button on the GitHub repository page to create a new repository based on this template.

### **2. Clone your new repository**

Clone your newly created repository to your local machine:

```sh
git clone https://github.com/your_username/your_new_repository.git --recursive
```

Or after clone the repo, you can update the git submodule with following commands:

```sh
git submodule update --init --recursive
```

### **3. Install dependencies**

For dependencies, it varies from distribution to distribution. You can refer to shell.nix and dockerfile for installation.

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
```

to install dependencies.

### **4. Build the project**

To build the project, run the following command:

```sh
make build
```

This will compile your code and create the necessary binaries. You can you the `Github Code space` or `Github Action` to build the project as well.

### ***Run the Project***

You can run the binary with:

```console
sudo src/xdp-pktgen
```

Or with Github Packages locally:

```console
docker run --rm -it --privileged -v $(pwd):/examples ghcr.io/eunomia-bpf/libbpf-template:latest
```

### **7. GitHub Actions**

This template also includes a GitHub action that will automatically build and publish your project when you push to the repository.
To customize this action, edit the **`.github/workflows/publish.yml`** file.

## **Contributing**

We welcome contributions to improve this template! If you have any ideas or suggestions,
feel free to create an issue or submit a pull request.

## **License**

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.
