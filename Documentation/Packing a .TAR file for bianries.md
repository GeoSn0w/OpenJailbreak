When building your jailbreak, you will likely need to deploy the base binaries of the jailbreak to the device when the jailbreak installs. This includes the standard `UNIX` binaries, `SSH` (Dropbear), and other command line tools you may want deployed, like `DPKG` and `APT`.

Most if not all jailbreaks use .TAR archives to deploy these. Having a few dozen Mach-O binaries in the root folder of the Xcode project and manually copying them one by one is not a great idea, so tarring them is a good solution. 

## Common issues when creating a bootstrap or base binaries tar file:

* You may accidentally include directory (folder) structures.
* You may add .DS_Store files or other annoying ".*" files.

## How to properly TAR your binaries (macOS).

1) Make a new folder on Desktop, call it basebins, then make another folder inside it and call it `jb`.
2) Inside the `jb` folder, add all the binaries you want with their proper folders and everything just like you want them to appear on the ROOT FS of the device. Make sure to not overwrite anything (don't make `/var` `/private` `/system` etc. folders yet).
3) Open Terminal and `cd` into the newly made `basebins` folder.
4) Run `tar cvf basebins.tar --exclude=".*" ./jb/`
5) This should create a new .tar file with all the binaries but not with .DS_Store, etc.

## For questions:

* GeoSn0w (@FCE365): https://twitter.com/FCE365
* YouTube: iDevice Central: https://www.youtube.com/fce365official
