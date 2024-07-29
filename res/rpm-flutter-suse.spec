Name:       moduloais
Version:    1.3.0
Release:    0
Summary:    RPM package
License:    GPL-3.0
Requires:   gtk3 libxcb1 xdotool libXfixes3 alsa-utils libXtst6 libappindicator-gtk3 libvdpau1 libva2 pam gstreamer-plugins-base gstreamer-plugin-pipewire
Provides:   libdesktop_drop_plugin.so()(64bit), libdesktop_multi_window_plugin.so()(64bit), libfile_selector_linux_plugin.so()(64bit), libflutter_custom_cursor_plugin.so()(64bit), libflutter_linux_gtk.so()(64bit), libscreen_retriever_plugin.so()(64bit), libtray_manager_plugin.so()(64bit), liburl_launcher_linux_plugin.so()(64bit), libwindow_manager_plugin.so()(64bit), libwindow_size_plugin.so()(64bit), libtexture_rgba_renderer_plugin.so()(64bit)

%description
The best open-source remote desktop client software, written in Rust.

%prep
# we have no source, so nothing here

%build
# we have no source, so nothing here

# %global __python %{__python3}

%install

mkdir -p "%{buildroot}/usr/lib/moduloais" && cp -r ${HBB}/flutter/build/linux/x64/release/bundle/* -t "%{buildroot}/usr/lib/moduloais"
mkdir -p "%{buildroot}/usr/bin"
install -Dm 644 $HBB/res/moduloais.service -t "%{buildroot}/usr/share/moduloais/files"
install -Dm 644 $HBB/res/moduloais.desktop -t "%{buildroot}/usr/share/moduloais/files"
install -Dm 644 $HBB/res/moduloais-link.desktop -t "%{buildroot}/usr/share/moduloais/files"
install -Dm 644 $HBB/res/128x128@2x.png "%{buildroot}/usr/share/icons/hicolor/256x256/apps/moduloais.png"
install -Dm 644 $HBB/res/scalable.svg "%{buildroot}/usr/share/icons/hicolor/scalable/apps/moduloais.svg"

%files
/usr/lib/moduloais/*
/usr/share/moduloais/files/moduloais.service
/usr/share/icons/hicolor/256x256/apps/moduloais.png
/usr/share/icons/hicolor/scalable/apps/moduloais.svg
/usr/share/moduloais/files/moduloais.desktop
/usr/share/moduloais/files/moduloais-link.desktop

%changelog
# let's skip this for now

# https://www.cnblogs.com/xingmuxin/p/8990255.html
%pre
# can do something for centos7
case "$1" in
  1)
    # for install
  ;;
  2)
    # for upgrade
    systemctl stop moduloais || true
  ;;
esac

%post
cp /usr/share/moduloais/files/moduloais.service /etc/systemd/system/moduloais.service
cp /usr/share/moduloais/files/moduloais.desktop /usr/share/applications/
cp /usr/share/moduloais/files/moduloais-link.desktop /usr/share/applications/
ln -s /usr/lib/moduloais/moduloais /usr/bin/moduloais
systemctl daemon-reload
systemctl enable moduloais
systemctl start moduloais
update-desktop-database

%preun
case "$1" in
  0)
    # for uninstall
    systemctl stop moduloais || true
    systemctl disable moduloais || true
    rm /etc/systemd/system/moduloais.service || true
  ;;
  1)
    # for upgrade
  ;;
esac

%postun
case "$1" in
  0)
    # for uninstall
    rm /usr/share/applications/moduloais.desktop || true
    rm /usr/share/applications/moduloais-link.desktop || true
    rm /usr/bin/moduloais || true
    update-desktop-database
  ;;
  1)
    # for upgrade
  ;;
esac
