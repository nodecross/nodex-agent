name "init-scripts"
ohai = Ohai::System.new
ohai.all_plugins

build do
  if ohai['platform_family'] == 'debian'
    etc_dir = "/etc/nodex-agent"
    systemd_directory = "/lib/systemd/system"
    erb source: "systemd.service.erb",
        dest: "#{systemd_directory}/nodex-agent.service",
        mode: 0644,
        vars: { install_dir: install_dir, etc_dir: etc_dir }
    project.extra_package_file "#{systemd_directory}/nodex-agent.service"
  elsif ohai['platform_family'] == 'mac_os_x'
    conf_dir = "#{install_dir}/etc"
    mkdir conf_dir
    erb source: "launchd.plist.erb",
        dest: "#{conf_dir}/com.nodex.nodex-agent.plist",
        mode: 0644,
        vars: { install_dir: install_dir }
    # project.extra_package_file "#{launchd_directory}/com.nodex.nodex-agent.plist"
  end
end
