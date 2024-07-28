Name:       moduloais
Version:    1.1.9
Release:    0
Summary:    RPM package
License:    GPL-3.0
Requires:   gtk3 libxcb1 xdotool libXfixes3 alsa-utils libXtst6 libayatana-appindicator3-1 libvdpau1 libva2 pam gstreamer-plugins-base gstreamer-plugin-pipewire

%description
The best open-source remote desktop client software, written in Rust.

%prep
# we have no source, so nothing here

%build
# we have no source, so nothing here

%global __python %{__python3}

%install
mkdir -p %{buildroot}/usr/bin/
mkdir -p %{buildroot}/usr/lib/moduloais/
mkdir -p %{buildroot}/usr/share/moduloais/files/
mkdir -p %{buildroot}/usr/share/icons/hicolor/256x256/apps/
mkdir -p %{buildroot}/usr/share/icons/hicolor/scalable/apps/
install -m 755 $HBB/target/release/moduloais %{buildroot}/usr/bin/moduloais
install $HBB/libsciter-gtk.so %{buildroot}/usr/lib/moduloais/libsciter-gtk.so
install $HBB/res/rustdesk.service %{buildroot}/usr/share/moduloais/files/
install $HBB/res/128x128@2x.png %{buildroot}/usr/share/icons/hicolor/256x256/apps/moduloais.png
install $HBB/res/scalable.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/moduloais.svg
install $HBB/res/moduloais.desktop %{buildroot}/usr/share/moduloais/files/
install $HBB/res/moduloais-link.desktop %{buildroot}/usr/share/moduloais/files/

%files
/usr/bin/moduloais
/usr/lib/moduloais/libsciter-gtk.so
/usr/share/moduloais/files/rustdesk.service
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
cp /usr/share/moduloais/files/rustdesk.service /etc/systemd/system/rustdesk.service
cp /usr/share/moduloais/files/moduloais.desktop /usr/share/applications/
cp /usr/share/moduloais/files/moduloais-link.desktop /usr/share/applications/
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
    rm /etc/systemd/system/rustdesk.service || true
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
    update-desktop-database
  ;;
  1)
    # for upgrade
  ;;
esac
