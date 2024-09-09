# nodex-agent Installation and Setup Guide

## How to Install by deb package

### Step 1: Download the deb package
Download the deb package from the [release page](https://github.com/nodecross/nodex/releases).

### Step 2: Install the package
Please run the following command. Be sure to replace the filename with the name of the file you downloaded.

```
dpkg -i /path/to/<downloaded_filename>.deb
```

## How to Execute nodex-agent

### Step 1: Set Configuration

#### When Adding Configuration for the First Time
Run the following commands to set the configuration. Note that these commands must be executed as the nodex user.

```
sudo -H -u nodex /usr/bin/nodex-agent --config network set --key project_did --value <your project_did>
sudo -H -u nodex /usr/bin/nodex-agent --config network set --key secret_key --value <your secret_key>
```

Replace <your project_did> and <your secret_key> with the actual values specific to your project.

#### If nodex Binary is Already Installed
Copy the .nodex directory and .config/nodex directory from the home directory of the user running nodex-agent to the home directory of the nodex user.
If you cannot find the appropriate directories, run the following command.

```
sudo find /home -type d ˶( -name “.nodex” -o -path “*/.config/nodex”˶) 2>/dev/null 
```

The following is an example of running as a user named hoge. Replace ``/home`` with the appropriate path for your environment.

```
sudo -u hoge cp -r /home/hoge/.nodex /home/hoge/.config/nodex /home/nodex/
```

Next, grant the nodex user read and write permissions on the copied directory.

```
sudo -u nodex chmod -R u+rw /home/nodex/.nodex /home/nodex/.config/nodex
```

### Step 2: Start the nodex-agent
Run the following command to start the nodex-agent.

```
systemctl start nodex-agent
```
