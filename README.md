# ClearKey OPTEE AOSP drm plugin

This plugin is based off the default AOSP SW ClearKey plugin
but uses OPTEE trusted application for the decryption. It has
been tested using ClearKey CENC test vectors played back
with ExoPlayer.

The ClearKey build with OP-TEE support is based on the Android Hikey
build described here:

https://github.com/linaro-swg/optee_android_manifest

## Preparation (for 64-bit platforms):

1a. [Android 8.0 and up] Define `TARGET_ENABLE_MEDIADRM_64=true` in
    BoardConfigCommon.mk.

1b. [Android 7.1] Retrieve and apply the framework/av patch from LHG-230.


## Preparation (for 32-bit platforms):

1. Configure OP-TEE to support 32-bit TA (`OPTEE_TA_TARGETS=ta_arm32`).

# Steps:

1. Clone this source code to external folder. By default, it will checkout the master branch.

```bash
  $ cd external
  $ git clone git@github.com:linaro-home/clearkeydrmplugin.git
  $ cd clearkeydrmplugin
  $ git clone git@github.com:linaro-home/optee-clearkey-cdmi.git
```

2. Add ClearKey test vectors to media.exolist.json in ExoPlayer

   Note earlier versions of ExoPlayer (pre 2.6.0) drm_scheme should be "cenc" not "clearkey".

```json
      {
           "name": "Big Buck Bunny fragment 20000ms (CENC ClearKey)",
           "uri": "https://people.linaro.org/~show.liu/bbb_clearkey/BigBuckBunny_enc_dash.mpd",
           "extension": "mpd",
           "drm_scheme": "clearkey",
           "drm_license_url": "https://people.linaro.org/~show.liu/clearkey/BigBuckBunny.json"
      },
      {
           "name": "Angel One (multicodec, multilingual, ClearKey server)",
           "uri": "http://storage.googleapis.com/shaka-demo-assets/angel-one-clearkey/dash.mpd",
           "extension": "mpd",
           "drm_scheme": "clearkey",
           "drm_license_url": "http://cwip-shaka-proxy.appspot.com/clearkey?_u3wDe7erb7v8Lqt8A3QDQ=ABEiM0RVZneImaq7zN3u_w"
      },
```

3. Build ExoPlayer.

   git: https://github.com/google/ExoPlayer.git

   Tested with SHA:

   >     commit e7c60a2a234ab11bc75335453a7836fef9509610
   >
   >     Merge: ab6f9ae 3562fe1
   >
   >     Author: ojw28 <olly@google.com>
   >
   >     Date:   Thu Nov 23 17:22:35 2017 +0000
   >
   >         Merge pull request #3493 from google/dev-v2-r2.6.0
   >
   >         r2.6.0

   A pre-built ExoPlayer-2.6.0 APK containing ClearKey samples can be downloaded found
   http://people.linaro.org/~peter.griffin/clearkey/exoplayer-2.6.0-clearkey-demo-withExtensions-debug.apk


4. Allow access to the tee device for non-root users:

```bash
   $ adb shell
   hikey/$ chmod ua+rw /dev/tee*
```

5. [Android 8.0 and up] For 64-bit platforms, configure the DRM HAL to search for 64-bit DRM plugins:

```bash
   $ adb shell
   hikey/$ setprop drm.64bit.enabled true
```

6. Run the Clearkey samples from ExoPlayer

   Ensure only `libdrmclearkeyopteeplugin.so` is installed under `/vendor/lib/mediadrm` partition.
   As otherwise you may use the default AOSP SW plugin (called `libdrmclearkeyplugin.so`).

## Notes

   make rule to rebuild OPTEE ClearKey mediadrm plugin
```bash
   make libdrmclearkeyopteeplugin
```
   make rule to rebuild OPTEE ClearKey TA
```bash
   make 442ed209-b8e2-405e-83845cc78c753428.ta
```
