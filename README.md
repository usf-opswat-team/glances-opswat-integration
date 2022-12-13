# Glances OPSWAT Integration

Integration of [MetaDefender Cloud](https://metadefender.opswat.com/) into [Glances](https://github.com/nicolargo/glances). A capstone Computer Science and Engineering project by students at the University of South Florida, Fall 2022. This integration allows you to use MetaDefender Cloud features such as single process scanning, continuous scanning off all processes, and the ability to see threat reports for running process displayed via Glances.

## Contributors

- Chuong Le
  - [GitHub](https://github.com/chuongle1994)
  - [LinkedIn](https://www.linkedin.com/in/chuong-le-aab0a217b/)
- Sebastian Rivera
  - [LinkedIn](https://www.linkedin.com/in/sebastianriv/)
  - [GitHub](https://github.com/01sebar)
- Jaylen Brown
  - [Github](https://github.com/JMarshalB)
  - [LinkedIn](https://www.linkedin.com/in/jaylen-brown-6a70511a3/) 
- Christopher Greenland
  - [Github](https://github.com/cgreenland)
- Eric Kemmer
  - [GitHub](https://github.com/Airick73)
  - [LinkedIn](https://www.linkedin.com/in/erickemmer/)

## Licensing

This repository contains modified code from the original Glances repository, and is thus subject to the licensing for the glances repository, which can be viewed here: https://github.com/nicolargo/glances

## Local Install Guide

This guide will outline how to install the OPSWAT MetaDefender Cloud implementation into Glances running on Ubuntu Desktop 22 LTS

## Install Glances

If you already have Glances installed, navigate to it's install directory. Once you've done this, continue to the install section.

### Cloning Glances

If you don't have Glances installed, here's a summary of instructions on how you could install Glances. Refer to the Glances website for more information on additional methods for installation.

We're going to want to clone glances into the root of our repo by following the instructions listed here: https://github.com/nicolargo/glances/wiki/Install-and-test-Glances-DEVELOP-version

1. `$ git clone -b develop https://github.com/nicolargo/glances.git`
2. `$ cd glances`
3. `$ git checkout develop`
4. `$ make venv-python`
5. `$ make venv`
6. `$ make run`

## Setup glances-opswat-plugin

Copy the glances-opswat-plugin folder so that it is on the same directory level of your Glances install, like the following:

```
foo_bar/
        glances/
            conf/
            glances/
            ... (more directories and files)
        glances-opswat-plugin/
            src/
            build.sh
            backup.sh
            restore.sh
            run.sh
```

## Get OPSWAT API Key

The OPSWAT API Key is needed to use the MetaDefender Cloud API. You can get a free API Key by creating an account here: https://id.opswat.com

Once you get you create your account and get your API Key, you'll want to add it to `glances-opswat-plugin/src/conf/opswat.json`

```
// glances-opswat-plugin/src/conf/opswat.json
{
    "api_key" : "SET_OPSWAT_API_KEY"
}
```

Replace `INSERT_API_KEY` with your API Key value. You'll want to run `./build.sh` whenever you modify this file so that it gets updated in the `glances/` directory.

## Backup

So the way the install works for the OPSWAT integration is by overwriting existing files within Glances. Our version of these files implement the necessary features for the MetaDefender Cloud scanning.

We can backup our current files in `/glances` by running:

`$ cd glances-opswat-plugin`

`$ ./backup.sh`

## Restore

If you want to restore your backed up files, you can do so by running:

`$ cd glances-opswat-plugin`

`$ ./restore.sh`

## Build

To copy our code from `glances-opswat-plugin/` into `glances/` we can run:

`$ cd glances-opswat-plugin`

`$ ./build.sh`

## Run

To run Glances, you can boot it up as you normally would. Or, you can use (though this may not work depending on your Glances install method):

`$ cd glances-opswat-plugin`

`$ ./run.sh`
