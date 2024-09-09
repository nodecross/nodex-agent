# Building the nodex-agent with Omnibus
To build the nodex-agent using Omnibus on a macOS system with the ARM architecture, follow these steps:

## Step 1: Set the Target Architecture and Platform

Before starting the build process, you need to export the environment variables to specify the target architecture and platform:

```
export TARGET_ARCH=aarch64-apple-darwin
export TARGET_PLATFORM=mac
```

## Step 2: Navigate to the Omnibus Directory

Change directory to the omnibus directory within the project:

```
cd omnibus
```

## Step 3: Run the Omnibus Build

Use the following command to start the Omnibus build process for the nodex-agent.
The sudo -E command ensures that the environment variables are preserved when running with elevated privileges.

```
sudo -E bin/omnibus build nodex-agent
```

This command will initiate the build process, creating the necessary packages for the nodex-agent.

