---
ID: 20250425015541
date: 2025-04-25
tags:
  - Blogging
Created: 2025-04-25:01:54:55
Last Modified: 2025-04-25:01:54:55
---
# Description

It is 25th April on a sleepless night (because I attempted to sleep early). Someone demonstrated how advertisements kept popping up in the Android phone even when no applications is on. Furthermore, it only happened after downloading an application that appeared on faCebOoK >:I
Because of that, she immediately uninstall the application that she has downloaded and could not remember the information about the application. After claiming to uninstall the application, the advertisement still pops out. The advertisement takes up the entire screen which disrupts normal usage of a phone every few seconds. Additionally, the more persistent applications were Google Play links to download other applications which succeeded. 

Of course, we can attempt to view all the current apps open but the window showing applications open has nothing to indicate which was the application at fault. 

With the goal of removing the invasive advertisements, I took the phone, turn off the WiFi, close all banking applications, turn on USB debugging mode and attach to ADB.

## TL;DR

Culprit APK was found after using ADB to list installed apk by installation date and found the review in google play to be damning. Since the phone has so many apps, I simply used ADB to uninstall the apk and restarted the phone. The APK does not seem to contain any other malicious functionalities like screensharing, remote control or contain full accessibility permissions.

# Figuring out the Culprit App
## Listing Third Party Packages by installation time

Here is the breakdown of the command that was provided by Claude. 
- `pm list packages -3`
	- `-3` reveals third party applications
- `sed 's/package://g` 
	- replaces `package:` with empty string
- `while read pkg; do install_time=$(dumpsys package $pkg | grep firstInstallTime); echo "$install_time - $pkg"; done` 
	- Treating each line as package name, `dumpsys` to get the first install time and append with the package name
- `sort -r`
	- Sort in reverse order starting from the most recent one
- `head -10`
	- List the first 10 items

![[Pasted image 20250425020913.png]]

## Getting the package manager path

```sh
pm path com.aoperifdso.vizwall

pm path com.spawn.clear.now.clean

pm path com.wavebeat.shine.ty
```

![[Pasted image 20250425015815.png]]

### Googling Package Names 

These applications are still available on Google Play at this point of writing. These were the confirmed applications that were downloaded earlier. 

![[Pasted image 20250425021020.png]]

![[Pasted image 20250425021033.png]]

![[Pasted image 20250425021046.png]]

### Review in Google Play Store

Looking at the review, it highly suggest that naughty award goes to Vizwall and it seems to act like an adware which is the same behaviour observed on the phone! It seems that this application had been deleted off in an attempt to rectify for the "mistake" of installing it but interestingly, the adware-like behaviour seem to persist.

![[Pasted image 20250425022314.png]]

### Extracting Vizwall

The following shows the extraction of the APK.

```
adb pull /data/app/~~XXXXXX==/com.aoperifdso.vizwall-XXXXX/base.apk vizwall.apk
adb pull /data/app/~~XXXXXX==/com.spawn.clear.now.clean-XXXXX/base.apk clean.apk
adb pull /data/app/~~XXXXXX==/com.wavebeat.shine.ty-XXXXX/base.apk wavebeat.apk
```

It seems that this application has been analyzed before and it seems that no solutions find this as malicious which is good since famous malware like spymax/spynote can be signatured pretty easily by these solutions.

![[Pasted image 20250425023950.png]]
## Vizwall Decompilation

The adware SHA256 : 97f85834fcc936d0f55d7d798cc5ef0a9f95dd7a055ce3003954b1aad9bcae0e
### Advertisement and Tracking Libraries 

Within JADX, we see that there are many advertising and tracking libraries like `applovin`, `tradplus`, `vungle.ads`, `appsflyer`, `applovin` and many more :O

![[Pasted image 20250425024408.png]]
### AndroidManifest.xml

#### Permissions

This application in Google Play is posting as a collection of wallpapers which users can download and easily set with one click. This makes sense for it to have `SET_WALLPAPER` per
```xml
<uses-permission android:name="android.permission.SET_WALLPAPER"/>
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
<uses-permission android:name="com.google.android.gms.permission.AD_ID"/>
<uses-permission android:name="android.permission.WAKE_LOCK"/>
<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
```

#### Persistence 

This application makes use of [RescheduleReceiver](https://androidx.de/androidx/work/impl/background/systemalarm/RescheduleReceiver.html) which `Reschedules alarms on BOOT_COMPLETED and other similar scenarios`. We see the permissions to `RECEIVE_BOOT_COMPLETED` has been set as well. 

##### Removing the Adware

We can easily get past this by doing an `adb` uninstall on the package and restart the phone just in case.

```xml
 <receiver
            android:name="androidx.work.impl.background.systemalarm.RescheduleReceiver"
	android:enabled="false"
	android:exported="false"
	android:directBootAware="false">
	<intent-filter>
		<action android:name="android.intent.action.BOOT_COMPLETED"/>
		<action android:name="android.intent.action.TIME_SET"/>
		<action android:name="android.intent.action.TIMEZONE_CHANGED"/>
	</intent-filter>
</receiver>
```

The APK has string obfuscation going on as well as some loaded native libraries. The string obfuscation is just a simple xor (8-bytes xor key).


#### Full AndroidManifest.xml

The following is the full dump of the Android Manifest file. 
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="20"
    android:versionName="2.0"
    android:compileSdkVersion="35"
    android:compileSdkVersionCodename="15"
    android:requiredSplitTypes="base__abi,base__density"
    android:splitTypes=""
    package="com.aoperifdso.vizwall"
    platformBuildVersionCode="35"
    platformBuildVersionName="15">
    <uses-sdk
        android:minSdkVersion="26"
        android:targetSdkVersion="35"/>
    <uses-permission android:name="android.permission.SET_WALLPAPER"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="com.google.android.gms.permission.AD_ID"/>
    <queries>
        <intent>
            <action android:name="androidx.browser.customtabs.CustomTabsService"/>
        </intent>
        <intent>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="https"/>
        </intent>
        <intent>
            <action android:name="android.intent.action.VIEW"/>
            <category android:name="android.intent.category.BROWSABLE"/>
            <data android:scheme="http"/>
        </intent>
        <intent>
            <action android:name="android.intent.action.VIEW"/>
            <data android:scheme="market"/>
        </intent>
        <package android:name="com.facebook.katana"/>
        <intent>
            <action android:name="com.appsflyer.referrer.INSTALL_PROVIDER"/>
        </intent>
        <package android:name="com.instagram.android"/>
        <package android:name="com.facebook.lite"/>
        <package android:name="com.samsung.android.mapsagent"/>
        <intent>
            <action android:name="com.applovin.am.intent.action.APPHUB_SERVICE"/>
        </intent>
        <intent>
            <action android:name="android.support.customtabs.action.CustomTabsService"/>
        </intent>
        <intent>
            <action android:name="android.intent.action.MAIN"/>
        </intent>
        <intent>
            <action android:name="android.intent.action.VIEW"/>
        </intent>
    </queries>
    <uses-permission android:name="android.permission.ACCESS_ADSERVICES_ATTRIBUTION"/>
    <uses-permission android:name="com.samsung.android.mapsagent.permission.READ_APP_INFO"/>
    <uses-permission android:name="com.huawei.appmarket.service.commondata.permission.GET_COMMON_DATA"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
    <uses-permission android:name="com.google.android.c2dm.permission.RECEIVE"/>
    <uses-permission android:name="android.permission.ACCESS_ADSERVICES_AD_ID"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="com.applovin.array.apphub.permission.BIND_APPHUB_SERVICE"/>
    <uses-permission android:name="com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE"/>
    <permission
        android:name="com.aoperifdso.vizwall.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
        android:protectionLevel="signature"/>
    <uses-permission android:name="com.aoperifdso.vizwall.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application
        android:theme="@style/Theme.VizWall"
        android:label="@string/viz_launcher_label"
        android:icon="@mipmap/viz_launcher_icon"
        android:name="com.viz.wall.good.App"
        android:allowBackup="true"
        android:hardwareAccelerated="true"
        android:supportsRtl="true"
        android:extractNativeLibs="false"
        android:fullBackupContent="@xml/appsflyer_backup_rules"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/tp_network_security_config"
        android:roundIcon="@mipmap/viz_launcher_icon_round"
        android:appComponentFactory="androidx.core.app.CoreComponentFactory"
        android:dataExtractionRules="@xml/appsflyer_data_extraction_rules">
        <activity
            android:name="com.viz.wall.good.liver.MainActivity"
            android:exported="true"/>
        <activity
            android:name="com.viz.wall.good.liver.InWallActivity"
            android:exported="true"/>
        <activity
            android:label="@string/app_name"
            android:icon="@mipmap/viz_wall_logo"
            android:name="com.viz.wall.good.liver.VizActivity"
            android:exported="true"
            android:excludeFromRecents="true"
            android:finishOnCloseSystemDialogs="true"
            android:roundIcon="@mipmap/viz_wall_logo">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
                <data
                    android:scheme="viz_wall"
                    android:host="com.viz.wall"/>
            </intent-filter>
        </activity>
        <activity-alias
            android:name="com.viz.wall.good.GateActivity"
            android:enabled="false"
            android:exported="true"
            android:excludeFromRecents="true"
            android:targetActivity="com.viz.wall.good.liver.VizActivity"
            android:finishOnCloseSystemDialogs="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity-alias>
        <activity
            android:name="com.viz.wall.good.VizInfoActivity"
            android:exported="true"
            android:excludeFromRecents="true"
            android:finishOnCloseSystemDialogs="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.INFO"/>
            </intent-filter>
        </activity>
        <activity
            android:theme="@style/BaseTheme"
            android:label=" "
            android:icon="@drawable/viz_robot_foreground"
            android:name="com.viz.wall.more.VizActivity"
            android:exported="true"
            android:excludeFromRecents="true"
            android:launchMode="singleTask"
            android:finishOnCloseSystemDialogs="true"/>
        <service
            android:name="com.viz.wall.more.chip.DrumService"
            android:exported="true"/>
        <service
            android:name="com.viz.wall.more.chip.StarService"
            android:exported="false"
            android:directBootAware="true">
            <intent-filter>
                <action android:name="com.google.firebase.MESSAGING_EVENT"/>
            </intent-filter>
        </service>
        <provider
            android:name="com.facebook.share.FacebookShareProvider"
            android:exported="true"
            android:authorities="com.aoperifdso.vizwall.share.rugby">
            <meta-data
                android:name="com.facebook.WebDialog"
                android:value="false"/>
            <meta-data
                android:name="@string/facebook_carry"
                android:value="@bool/facebook_seat"/>
            <meta-data
                android:name="com.facebook.appevents.AppEventDiskStore"
                android:value="false"/>
        </provider>
        <activity
            android:name="com.kwai.network.framework.adCommon.activity.AllianceEmptyShellActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:screenOrientation="portrait"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.NoTitleBar"
            android:name="com.inmobi.ads.rendering.InMobiAdActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"
            android:hardwareAccelerated="true"/>
        <activity
            android:name="com.vungle.ads.internal.ui.VungleActivity"
            android:excludeFromRecents="true"
            android:launchMode="singleTop"
            android:configChanges="smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"
            android:hardwareAccelerated="true"/>
        <activity
            android:theme="@style/tt_landing_page"
            android:name="com.bytedance.sdk.openadsdk.activity.TTLandingPageActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_landing_page"
            android:name="com.bytedance.sdk.openadsdk.activity.TTPlayableLandingPageActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_landing_page"
            android:name="com.bytedance.sdk.openadsdk.activity.TTVideoLandingPageLink2Activity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Translucent.NoTitleBar"
            android:name="com.bytedance.sdk.openadsdk.activity.TTDelegateActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_privacy_landing_page"
            android:name="com.bytedance.sdk.openadsdk.activity.TTWebsiteActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:screenOrientation="portrait"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_app_open_ad_no_animation"
            android:name="com.bytedance.sdk.openadsdk.activity.TTAppOpenAdActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_full_screen_new"
            android:name="com.bytedance.sdk.openadsdk.activity.TTRewardVideoActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_full_screen_new"
            android:name="com.bytedance.sdk.openadsdk.activity.TTRewardExpressVideoActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_full_screen_new"
            android:name="com.bytedance.sdk.openadsdk.activity.TTFullScreenVideoActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_full_screen_new"
            android:name="com.bytedance.sdk.openadsdk.activity.TTFullScreenExpressVideoActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_full_screen_interaction"
            android:name="com.bytedance.sdk.openadsdk.activity.TTInterstitialActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_full_screen_interaction"
            android:name="com.bytedance.sdk.openadsdk.activity.TTInterstitialExpressActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/tt_full_screen_new"
            android:name="com.bytedance.sdk.openadsdk.activity.TTAdActivity"
            android:excludeFromRecents="true"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Translucent.NoTitleBar"
            android:name="com.tp.adx.sdk.ui.InnerWebViewActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.NoTitleBar"
            android:name="com.tp.adx.sdk.ui.InnerActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Translucent.NoTitleBar.Fullscreen"
            android:name="com.tradplus.ads.mgr.interstitial.views.InterNativeActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:launchMode="singleTask"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
            android:name="com.tradplus.crosspro.ui.CPAdActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:configChanges="screenSize|orientation|keyboardHidden|keyboard"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Translucent.NoTitleBar.Fullscreen"
            android:name="com.tradplus.crosspro.ui.ApkConfirmDialogActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme"
            android:name="sg.bigo.ads.ad.splash.AdSplashActivity"
            android:excludeFromRecents="true"
            android:screenOrientation="portrait"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme"
            android:name="sg.bigo.ads.ad.splash.LandscapeAdSplashActivity"
            android:excludeFromRecents="true"
            android:screenOrientation="landscape"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:name="sg.bigo.ads.controller.form.AdFormActivity"
            android:excludeFromRecents="true"
            android:windowSoftInputMode="adjustPan"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Holo.Light.NoActionBar"
            android:name="sg.bigo.ads.api.AdActivity"
            android:excludeFromRecents="true"
            android:screenOrientation="portrait"
            android:configChanges="screenSize|orientation"
            android:windowSoftInputMode="stateAlwaysHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Holo.Light.Dialog.NoActionBar"
            android:name="sg.bigo.ads.api.LandingStyleableActivity"
            android:excludeFromRecents="true"
            android:screenOrientation="portrait"
            android:configChanges="screenSize|orientation"
            android:windowSoftInputMode="stateAlwaysHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Holo.Light.NoActionBar"
            android:name="sg.bigo.ads.api.LandscapeAdActivity"
            android:excludeFromRecents="true"
            android:screenOrientation="landscape"
            android:configChanges="screenSize|orientation"
            android:windowSoftInputMode="stateAlwaysHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Holo.Light.NoActionBar"
            android:name="sg.bigo.ads.api.CompanionAdActivity"
            android:excludeFromRecents="true"
            android:screenOrientation="portrait"
            android:configChanges="screenSize|orientation"
            android:windowSoftInputMode="stateAlwaysHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Holo.Light.NoActionBar"
            android:name="sg.bigo.ads.api.LandscapeCompanionAdActivity"
            android:excludeFromRecents="true"
            android:screenOrientation="landscape"
            android:configChanges="screenSize|orientation"
            android:windowSoftInputMode="stateAlwaysHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
            android:name="sg.bigo.ads.core.mraid.MraidVideoActivity"
            android:excludeFromRecents="true"
            android:screenOrientation="portrait"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Translucent.NoTitleBar"
            android:name="com.mbridge.msdk.reward.player.MBRewardVideoActivity"
            android:excludeFromRecents="true"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.Translucent.NoTitleBar"
            android:name="com.mbridge.msdk.newreward.player.MBRewardVideoActivity"
            android:excludeFromRecents="true"
            android:configChanges="screenSize|orientation|keyboardHidden"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/mbridge_transparent_common_activity_style"
            android:name="com.mbridge.msdk.activity.MBCommonActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:configChanges="orientation|keyboard"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:name="com.mbridge.msdk.out.LoadingActivity"
            android:excludeFromRecents="true"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
            android:name="com.applovin.adview.AppLovinFullscreenActivity"
            android:exported="false"
            android:excludeFromRecents="true"
            android:launchMode="singleTop"
            android:screenOrientation="behind"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"
            android:hardwareAccelerated="true"/>
        <activity
            android:name="com.applovin.sdk.AppLovinWebViewActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
            android:name="com.applovin.mediation.hybridAds.MaxHybridMRecAdActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
            android:name="com.applovin.mediation.hybridAds.MaxHybridNativeAdActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerDetailActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerMultiAdActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerAdUnitsListActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerAdUnitWaterfallsListActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerAdUnitDetailActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerCmpNetworksListActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerTcfConsentStatusesListActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerTcfInfoListActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerTcfStringActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerTestLiveNetworkActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerTestModeNetworkActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerUnifiedFlowActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.mediation.MaxDebuggerActivity.Theme"
            android:name="com.applovin.mediation.MaxDebuggerWaterfallSegmentsActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.creative.CreativeDebuggerActivity.Theme"
            android:name="com.applovin.creative.MaxCreativeDebuggerActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <activity
            android:theme="@style/com.applovin.creative.CreativeDebuggerActivity.Theme"
            android:name="com.applovin.creative.MaxCreativeDebuggerDisplayedAdActivity"
            android:excludeFromRecents="true"
            android:configChanges="fontScale|smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden|keyboard|locale"
            android:finishOnCloseSystemDialogs="true"/>
        <provider
            android:name="com.squareup.picasso.PicassoProvider"
            android:exported="false"
            android:authorities="com.aoperifdso.vizwall.com.squareup.picasso"/>
        <activity
            android:theme="@style/com_facebook_activity_theme"
            android:name="com.facebook.FacebookActivity"
            android:configChanges="screenSize|screenLayout|orientation|keyboardHidden|keyboard"/>
        <activity android:name="com.facebook.CustomTabMainActivity"/>
        <activity
            android:name="com.facebook.CustomTabActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data
                    android:scheme="fbconnect"
                    android:host="cct.com.aoperifdso.vizwall"/>
            </intent-filter>
        </activity>
        <service
            android:name="com.google.firebase.components.ComponentDiscoveryService"
            android:exported="false"
            android:directBootAware="true">
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.analytics.ktx.FirebaseAnalyticsLegacyRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.remoteconfig.ktx.FirebaseConfigLegacyRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.messaging.ktx.FirebaseMessagingLegacyRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.remoteconfig.FirebaseRemoteConfigKtxRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.remoteconfig.RemoteConfigRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.messaging.FirebaseMessagingKtxRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.messaging.FirebaseMessagingRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.analytics.connector.internal.AnalyticsConnectorRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.installations.FirebaseInstallationsKtxRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.installations.FirebaseInstallationsRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.ktx.FirebaseCommonLegacyRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.FirebaseCommonKtxRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.abt.component.AbtRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
            <meta-data
                android:name="com.google.firebase.components:com.google.firebase.datatransport.TransportRegistrar"
                android:value="com.google.firebase.components.ComponentRegistrar"/>
        </service>
        <receiver
            android:name="com.google.firebase.messaging.directboot.FirebaseMessagingDirectBootReceiver"
            android:permission="com.google.android.c2dm.permission.SEND"
            android:exported="true"
            android:directBootAware="true">
            <intent-filter>
                <action android:name="com.google.firebase.messaging.RECEIVE_DIRECT_BOOT"/>
            </intent-filter>
        </receiver>
        <receiver
            android:name="com.google.firebase.iid.FirebaseInstanceIdReceiver"
            android:permission="com.google.android.c2dm.permission.SEND"
            android:exported="true">
            <intent-filter>
                <action android:name="com.google.android.c2dm.intent.RECEIVE"/>
            </intent-filter>
            <meta-data
                android:name="com.google.android.gms.cloudmessaging.FINISHED_AFTER_HANDLED"
                android:value="true"/>
        </receiver>
        <service
            android:name="com.google.firebase.messaging.FirebaseMessagingService"
            android:exported="false"
            android:directBootAware="true">
            <intent-filter android:priority="-500">
                <action android:name="com.google.firebase.MESSAGING_EVENT"/>
            </intent-filter>
        </service>
        <property
            android:name="android.adservices.AD_SERVICES_CONFIG"
            android:resource="@xml/ga_ad_services_config"/>
        <provider
            android:name="androidx.startup.InitializationProvider"
            android:exported="false"
            android:authorities="com.aoperifdso.vizwall.androidx-startup">
            <meta-data
                android:name="androidx.work.WorkManagerInitializer"
                android:value="androidx.startup"/>
            <meta-data
                android:name="androidx.emoji2.text.EmojiCompatInitializer"
                android:value="androidx.startup"/>
            <meta-data
                android:name="androidx.lifecycle.ProcessLifecycleInitializer"
                android:value="androidx.startup"/>
            <meta-data
                android:name="androidx.profileinstaller.ProfileInstallerInitializer"
                android:value="androidx.startup"/>
        </provider>
        <service
            android:name="androidx.work.impl.background.systemalarm.SystemAlarmService"
            android:enabled="@bool/enable_system_alarm_service_default"
            android:exported="false"
            android:directBootAware="false"/>
        <service
            android:name="androidx.work.impl.background.systemjob.SystemJobService"
            android:permission="android.permission.BIND_JOB_SERVICE"
            android:enabled="@bool/enable_system_job_service_default"
            android:exported="true"
            android:directBootAware="false"/>
        <service
            android:name="androidx.work.impl.foreground.SystemForegroundService"
            android:enabled="@bool/enable_system_foreground_service_default"
            android:exported="false"
            android:directBootAware="false"/>
        <receiver
            android:name="androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver"
            android:enabled="true"
            android:exported="false"
            android:directBootAware="false"/>
        <receiver
            android:name="androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy"
            android:enabled="false"
            android:exported="false"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="android.intent.action.ACTION_POWER_CONNECTED"/>
                <action android:name="android.intent.action.ACTION_POWER_DISCONNECTED"/>
            </intent-filter>
        </receiver>
        <receiver
            android:name="androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy"
            android:enabled="false"
            android:exported="false"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="android.intent.action.BATTERY_OKAY"/>
                <action android:name="android.intent.action.BATTERY_LOW"/>
            </intent-filter>
        </receiver>
        <receiver
            android:name="androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy"
            android:enabled="false"
            android:exported="false"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="android.intent.action.DEVICE_STORAGE_LOW"/>
                <action android:name="android.intent.action.DEVICE_STORAGE_OK"/>
            </intent-filter>
        </receiver>
        <receiver
            android:name="androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy"
            android:enabled="false"
            android:exported="false"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="android.net.conn.CONNECTIVITY_CHANGE"/>
            </intent-filter>
        </receiver>
        <receiver
            android:name="androidx.work.impl.background.systemalarm.RescheduleReceiver"
            android:enabled="false"
            android:exported="false"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
                <action android:name="android.intent.action.TIME_SET"/>
                <action android:name="android.intent.action.TIMEZONE_CHANGED"/>
            </intent-filter>
        </receiver>
        <receiver
            android:name="androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver"
            android:enabled="@bool/enable_system_alarm_service_default"
            android:exported="false"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="androidx.work.impl.background.systemalarm.UpdateProxies"/>
            </intent-filter>
        </receiver>
        <receiver
            android:name="androidx.work.impl.diagnostics.DiagnosticsReceiver"
            android:permission="android.permission.DUMP"
            android:enabled="true"
            android:exported="true"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="androidx.work.diagnostics.REQUEST_DIAGNOSTICS"/>
            </intent-filter>
        </receiver>
        <service
            android:name="androidx.room.MultiInstanceInvalidationService"
            android:exported="false"
            android:directBootAware="true"/>
        <provider
            android:name="com.applovin.sdk.AppLovinInitProvider"
            android:exported="false"
            android:authorities="com.aoperifdso.vizwall.applovininitprovider"
            android:initOrder="101"/>
        <service
            android:name="com.applovin.impl.adview.activity.FullscreenAdService"
            android:exported="false"
            android:stopWithTask="false"/>
        <receiver
            android:name="com.google.android.gms.measurement.AppMeasurementReceiver"
            android:enabled="true"
            android:exported="false"/>
        <service
            android:name="com.google.android.gms.measurement.AppMeasurementService"
            android:enabled="true"
            android:exported="false"/>
        <service
            android:name="com.google.android.gms.measurement.AppMeasurementJobService"
            android:permission="android.permission.BIND_JOB_SERVICE"
            android:enabled="true"
            android:exported="false"/>
        <activity
            android:theme="@android:style/Theme.Translucent.NoTitleBar"
            android:name="com.google.android.gms.common.api.GoogleApiActivity"
            android:exported="false"/>
        <provider
            android:name="com.google.firebase.provider.FirebaseInitProvider"
            android:exported="false"
            android:authorities="com.aoperifdso.vizwall.firebaseinitprovider"
            android:initOrder="100"
            android:directBootAware="true"/>
        <uses-library
            android:name="android.ext.adservices"
            android:required="false"/>
        <meta-data
            android:name="com.google.android.gms.version"
            android:value="@integer/google_play_services_version"/>
        <meta-data
            android:name="com.bytedance.sdk.pangle.version"
            android:value="6.5.0.3"/>
        <activity
            android:name="com.bytedance.sdk.openadsdk.activity.TTCeilingLandingPageActivity"
            android:launchMode="standard"
            android:configChanges="screenSize|orientation|keyboardHidden"/>
        <service android:name="com.bytedance.sdk.openadsdk.multipro.aidl.BinderPoolService"/>
        <receiver
            android:name="com.facebook.CurrentAccessTokenExpirationBroadcastReceiver"
            android:exported="false">
            <intent-filter>
                <action android:name="com.facebook.sdk.ACTION_CURRENT_ACCESS_TOKEN_CHANGED"/>
            </intent-filter>
        </receiver>
        <receiver
            android:name="com.facebook.AuthenticationTokenManager$CurrentAuthenticationTokenChangedBroadcastReceiver"
            android:exported="false">
            <intent-filter>
                <action android:name="com.facebook.sdk.ACTION_CURRENT_AUTHENTICATION_TOKEN_CHANGED"/>
            </intent-filter>
        </receiver>
        <service
            android:name="com.google.android.datatransport.runtime.backends.TransportBackendDiscovery"
            android:exported="false">
            <meta-data
                android:name="backend:com.google.android.datatransport.cct.CctBackendFactory"
                android:value="cct"/>
        </service>
        <receiver
            android:name="androidx.profileinstaller.ProfileInstallReceiver"
            android:permission="android.permission.DUMP"
            android:enabled="true"
            android:exported="true"
            android:directBootAware="false">
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.INSTALL_PROFILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.SKIP_FILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.SAVE_PROFILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.BENCHMARK_OPERATION"/>
            </intent-filter>
        </receiver>
        <service
            android:name="com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService"
            android:permission="android.permission.BIND_JOB_SERVICE"
            android:exported="false"/>
        <receiver
            android:name="com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver"
            android:exported="false"/>
        <activity
            android:theme="@android:style/Theme.Black.NoTitleBar.Fullscreen"
            android:name="com.tradplus.ads.mgr.interstitial.views.InterNativeAPI26Activity"
            android:exported="false"
            android:launchMode="singleTask"
            android:configChanges="screenSize|orientation|keyboardHidden"/>
        <activity
            android:theme="@android:style/Theme.Translucent.NoTitleBar.Fullscreen"
            android:name="com.tradplus.crosspro.ui.ApkConfirmDialogCNActivity"
            android:exported="true"/>
        <activity
            android:theme="@android:style/Theme.NoTitleBar.Fullscreen"
            android:name="com.vungle.warren.ui.VungleActivity"
            android:launchMode="singleTop"
            android:configChanges="smallestScreenSize|screenSize|uiMode|screenLayout|orientation|keyboardHidden"/>
        <receiver
            android:name="com.mbridge.msdk.foundation.same.broadcast.NetWorkChangeReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="android.net.conn.CONNECTIVITY_CHANGE"/>
            </intent-filter>
        </receiver>
        <provider
            android:name="sg.bigo.ads.controller.provider.BigoAdsProvider"
            android:exported="false"
            android:authorities="com.aoperifdso.vizwall.BigoAdsProvider"/>
        <activity
            android:theme="@style/TransparentDialog"
            android:name="sg.bigo.ads.api.PopupAdActivity"
            android:screenOrientation="portrait"
            android:configChanges="screenSize|orientation"
            android:windowSoftInputMode="stateAlwaysHidden"/>
        <activity
            android:name="com.pairip.licensecheck.LicenseActivity"
            android:exported="false"/>
        <provider
            android:name="com.pairip.licensecheck.LicenseContentProvider"
            android:exported="false"
            android:authorities="com.aoperifdso.vizwall.com.pairip.licensecheck.LicenseContentProvider"/>
        <meta-data
            android:name="com.android.vending.splits.required"
            android:value="true"/>
        <meta-data
            android:name="com.android.stamp.source"
            android:value="https://play.google.com/store"/>
        <meta-data
            android:name="com.android.stamp.type"
            android:value="STAMP_TYPE_DISTRIBUTION_APK"/>
        <meta-data
            android:name="com.android.vending.splits"
            android:resource="@xml/splits0"/>
        <meta-data
            android:name="com.android.vending.derived.apk.id"
            android:value="3"/>
    </application>
    <uses-permission android:name="com.android.vending.CHECK_LICENSE"/>
</manifest>
```

# Conclusion

That someone I know was on Facebook and got the idea from I-dont-know-how-or-what that by installing some application, she can continue to watch some videos in it (bizarre). From there, since it is Google Play Store, it gave a false impression that it cant be anything mischievous which led to the download and installation of the adware. Thankfully, the APK is not thing malware like spynote or spymax which could lead to monetary loss.

Finally, while the reason was really bizarre, it shows that anything can happen and it pays to be extra vigilant and to spread the word of caution! 