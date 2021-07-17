# DGA detector

## Use cases
### DGA detector
To try detector follow these steps:

Important: module has to be [installed](#installation)

```
./dga_detector -i f:realdata,f:/dev/stdout | logger -i f:/dev/stdin
```

### Create decision tree
To create decision tree follow these steps:

Important: [Scikit-learn](https://scikit-learn.org/stable/index.html), [Sklearn-porter](https://pypi.org/project/sklearn-porter/0.4.0/), [Numpy](https://numpy.org/), [Pandas](https://pandas.pydata.org/) and [Python](https://www.python.org/) has to be installed

To install dependecies:
```
pip install pandas scikit-learn==0.22 numpy sklearn-porter
```

To create decision tree classifier
```
unzip dataset.zip
python ./create_tree.py train_dataset.csv 
```


## Installation
Follow these steps:

Important: [Nemea framework](#dependencies) has to be compiled (or installed) in advance.

1) Let Autotools process the configuration files.
```
autoreconf -i
```

2) Configure the module directory.
```
./configure
```

3) Build the module.
```
make
```

4) Install the module. The command should be performed as root (e.g. using sudo).
```
make install
```



## Description
This module contains detector of DGA adresses.

## Interfaces
- Inputs: 1
- Outputs: 1

### Input data
DNS flow data in UniRec format.

### Output data
Capture time and domain name classifed as DGA in UniRec format.

## Parameters

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Module recives UniRec format containing domain names and additional data. Features of adresses are computed. Based on features prediction of DGA is made. Module uses machine learning technique specifically algortihm of decison tree.

## Troubleshooting
### Loading shared libraries
In case the example module fails with:
```
error while loading shared libraries: libtrap.so.1: cannot open shared object file: No such file or directory
```
please, make sure that libtrap is installed on the system.
If installed ```ldconfig``` should help.
It is also possible to use libtrap that is not installed yet -- in this case, use:
```
export LD_LIBRARY_PATH=../../libtrap/src/.libs/
```
where `../../libtrap/src/.libs/` is the relative path from the `examples/module` directory in the downloaded and compiled Nemea-Framework repository.

### TRAP parameters
In case the example module fails with:
```
ERROR in parsing of parameters for TRAP: Interface specifier (option -i) not found.
```
It means you haven't provided the parameters required by the TRAP library. For more information run the module with `-h trap` parameter.
<br/><br/><br/>

# Dependencies 
# NEMEA installation

There are three different ways of installation of the NEMEA system covered
in this document: **vagrant**, **binary packages** and **source codes**.


## Vagrant

To try the system "out-of-box", you can use [Vagrant](https://www.vagrantup.com/).
For more information see [./vagrant/](./vagrant/).


## Binary packages

Latest RPM packages can be found in COPR: https://copr.fedorainfracloud.org/groups/g/CESNET/coprs/
The NEMEA repository is at https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/

The repository can be added trough `dnf copr enable` or by using the following commands (for CentOS/Fedora):

```
wget -O /etc/yum.repos.d/cesnet-nemea.repo https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/repo/epel-7/group_CESNET-NEMEA-epel-7.repo
rpm --import https://copr-be.cloud.fedoraproject.org/results/@CESNET/NEMEA/pubkey.gpg
```

After installation of the COPR repository, NEMEA can be installed as any other package (run as root/sudo):

```
yum install nemea
```

Note: Latest systems (e.g. Fedora) use `dnf` instead of `yum`.

For development purposes, there is `nemea-framework-devel` package that installs
all needed development files and docs. To install this package, also add the `NEMEA-testing` repository.

Currently, we do not have .deb packages (for Debian/Ubuntu/...) but we are working on it. Please follow installation from [source codes](#source-codes)

## Source codes

The whole system is based on GNU/Autotools build system that makes dependency checking and
building process much more easier.

To clone the NEMEA repositories, use:

```
git clone --recursive https://github.com/CESNET/nemea
```

After successful clone and [dependencies](#dependencies) installation (**!**), use:

```
./bootstrap.sh
```

that will create `configure` scripts and other needed files.

The `configure` script supplies various possibilities of
configuration and it uses some environmental variables that influence the build
and compilation process. For more information see:

```
./configure --help
```

We recommend to set paths according to the used operating system, e.g.:

```
./configure --enable-repobuild --prefix=/usr --bindir=/usr/bin/nemea --sysconfdir=/etc/nemea --libdir=/usr/lib64
```

After finishing `./configure`, build process can be started by:

```
make
```

The make(1) tool has various parameters, to build the NEMEA package faster on
multicore systems, we recommend to use parameter -j with the number of jobs
that should be run in parallel.

When the compilation process ends without any error, the package can be installed
into paths that were set by `configure`. It is recommended NOT to change
target paths by passing variables directly to make(1).
The installation can be done by (usually it requires root / sudo):

```
make install
```

Congratulations, the whole NEMEA system should be installed right now... :-)


