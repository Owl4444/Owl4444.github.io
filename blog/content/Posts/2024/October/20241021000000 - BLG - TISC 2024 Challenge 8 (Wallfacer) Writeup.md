---
ID: 20241021000000
tags:
  - Blogging
  - Writeup
  - Android
  - Patching
Created: 2024-10-21 17:22:00
Last Modified: 2024-10-21 17:22:00
date: 2024/10/21
---

![[Pasted image 20241111155534.png]]

# Description

TISC 2024 Challenge 8, titled "WallFacer," is an APK reverse engineering challenge that requires bypassing multiple walls through patching. While it is possible to solve this challenge using tools like Frida to manipulate process memory, I opted for the route of directly patching the APK.

Throughout this challenge, I gained deeper insight into repackaging APKs by modifying the binary. Reflecting on previous encounters with mobile malware samples, patching binaries to bypass security mitigations is not uncommon. Attackers often need to circumvent additional security measures and integrity checks. This challenge has given me a greater appreciation for the techniques involved. 

# Setup

## Emulator (RootAVD)
I set up a typical Android emulator environment using rootAVD, running on x86-64 Windows.

```bash
rootAVD.bat system-images\android-35\google_apis_playstore\x86_64\ramdisk.img
```

# The Initial Look

## MainActivity
The challenge begins with the MainActivity of the APK.

![[Pasted image 20241111155547.png]]

Inspecting the AndroidManifest.xml file reveals two activities: `com.wall.facer.MainActivity` and `com.wall.facer.query`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="1"
    android:versionName="1.0"
    android:compileSdkVersion="34"
    android:compileSdkVersionCodename="14"
    package="com.wall.facer"
    platformBuildVersionCode="34"
    platformBuildVersionName="14">
    <uses-sdk
        android:minSdkVersion="33"
        android:targetSdkVersion="34"/>
    <permission
        android:name="com.wall.facer.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
        android:protectionLevel="signature"/>
    <uses-permission android:name="com.wall.facer.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application
        android:theme="@style/Theme.Wallfacer"
        android:label="@string/app_name"
        android:icon="@mipmap/ic_launcher"
        android:name="com.wall.facer.app"
        android:allowBackup="true"
        android:supportsRtl="true"
        android:extractNativeLibs="false"
        android:fullBackupContent="@xml/backup_rules"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:appComponentFactory="androidx.core.app.CoreComponentFactory"
        android:dataExtractionRules="@xml/data_extraction_rules">
        <activity
            android:name="com.wall.facer.query"
            android:exported="true"/>
        <activity
            android:name="com.wall.facer.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider
            android:name="androidx.startup.InitializationProvider"
            android:exported="false"
            android:authorities="com.wall.facer.androidx-startup">
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
    </application>
</manifest>
```

### Decompilation of MainActivity

At first glance, `MainActivity` appears simple and doesn't seem to provide much useful information. However, it plays a crucial role later in the challenge.
```java
package com.wall.facer;

import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import defpackage.C0;

/* loaded from: classes.dex */
public class MainActivity extends C0 {
    public EditText y;

    @Override // defpackage.C0, defpackage.O3, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        this.y = (EditText) findViewById(R.id.edit_text);
    }

    public void onSubmitClicked(View view) {
        Storage.getInstance().saveMessage(this.y.getText().toString());
    }
}
```

## Query Activity

### Switching from MainActivity

To switch between MainActivity and query, use the following commands:

```bash
# Get to query 
adb shell am start -n com.wall.facer/.query

# Get to main activity
adb shell am start -n com.wall.facer/.MainActivity
```

Switching to the `query` activity prompts for a key and IV value.

![[Pasted image 20241111155600.png]]

### Decompilation

Decompiling the `query` activity shows that it requires a key and IV for AES encryption in CBC mode.

```java
package com.wall.facer;

import android.content.Context;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import defpackage.C0;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes.dex */
public class query extends C0 {
    public EditText y;
    public EditText z;

    @Override // defpackage.C0, defpackage.O3, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_query);
        this.y = (EditText) findViewById(R.id.key_text);
        this.z = (EditText) findViewById(R.id.iv_text);
    }

    public void onSubmitClicked(View view) {
        Context applicationContext = getApplicationContext();
        String obj = this.y.getText().toString();
        String obj2 = this.z.getText().toString();
        try {
            byte[] decode = Base64.decode(applicationContext.getString(R.string.str), 0);
            byte[] bytes = obj.getBytes();
            byte[] bytes2 = obj2.getBytes();
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(2, new SecretKeySpec(bytes, "AES"), new IvParameterSpec(bytes2));
            Log.d(getString(R.string.tag), "Decrypted data: ".concat(new String(cipher.doFinal(decode))));
        } catch (Exception unused) {
            Log.e(getString(R.string.tag), "Failed to decrypt data");
        }
    }
}
```

### Encrypted Flag

The encrypted flag is Base64 encoded and can be found in `res/values/strings.xml`.

```xml
<string name="str">4tYKEbM6WqQcItBx0GMJvssyGHpVTJMhpjxHVLEZLVK6cmIH7jAmI/nwEJ1gUDo2</string>
```

## Sqlite.db is database... or is it?

Examining the strings in the XML file, we find a Base64 value. Decoding it gives us `wallowinpain`.

![[Pasted image 20241111155610.png]]

There's also a Base64 encoded string for `sqlite.db`.

![[Pasted image 20241111155636.png]]

![[Pasted image 20241111155621.png]]

Tracing the ID of the string `filename` leads to `K0.smali`. Interestingly, the decompilation for this function failed.

Interestingly, the decompilation for this function failed.

![[Pasted image 20241111155645.png]]

However, by searching the smali code for the loading of this constant, we identify its usage.

```c
    const v0, 0x7f0f0038   <_----------- BASE64 of "sqlite.db"

    :try_start_0
    invoke-virtual {p0, v0}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/String;

    const/4 v2, 0x0

    invoke-static {v0, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/String;-><init>([B)V

    invoke-static {p0, v1}, LA8;->K(Landroid/content/Context;Ljava/lang/String;)Ljava/nio/ByteBuffer;

    move-result-object v0

    new-instance v1, Ldalvik/system/InMemoryDexClassLoader;

    invoke-virtual {p0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v2

    invoke-direct {v1, v0, v2}, Ldalvik/system/InMemoryDexClassLoader;-><init>(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V

    const-string v0, "DynamicClass"

    invoke-virtual {v1, v0}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object v0

    const-class v1, Landroid/content/Context;

    filled-new-array {v1}, [Ljava/lang/Class;

    move-result-object v1

    const-string v2, "dynamicMethod"

    invoke-virtual {v0, v2, v1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const/4 v1, 0x0

    invoke-virtual {v0, v1, p0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void
```

### Sqlite.db as Encrypted DEX File

In the previous smali snippet, the base64 string of `sqlite.db` was loaded to constant before it was decoded to `sqlite.db` string. A `InMemoryDexClassLoader` was then instantiated, which loads `sqlite.db` as a class  and run after it was being decrypted via `A8.K(context, "sqlite.db")`.

```c
    invoke-static {v0, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/String;-><init>([B)V

    invoke-static {p0, v1}, LA8;->K(Landroid/content/Context;Ljava/lang/String;)Ljava/nio/ByteBuffer;

    move-result-object v0

    new-instance v1, Ldalvik/system/InMemoryDexClassLoader;
```

### Decrypting Sqlite.db content

The `sqlite.db` file is actually an encrypted DEX file. The decryption routine reads the file, extracts the length of the encrypted data and the key, and then performs RC4 decryption.

#### Data Structure of Sqlite.db

Ultimately, this is what the `sqlite.db` file contain:

|Data|Length(bytes)|Description|
|---|---|---|
|Unused|0x1000| Unused sqlite header and more|
|Length of Enc. Data|0x4|How much data to get for decryption|
|Key|0x80|RC4 Key|
|Encrypted Data|Length of Enc. Data| Encrypted Dex file|


```java
public static ByteBuffer K(Context context, String str) {
        int i2;
        InputStream open = context.getAssets().open(str);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] bArr = new byte[1024];
        while (true) {
            int read = open.read(bArr);
            if (read == -1) {
                break;
            }
            byteArrayOutputStream.write(bArr, 0, read);
        }
        open.close();
        byte[] byteArray = byteArrayOutputStream.toByteArray(); 

        // RC4 KEY
        byte[] bArr2 = new byte[128];
        // Encrypted Data Length
        byte[] bArr3 = new byte[4];

        System.arraycopy(byteArray, 4096, bArr3, 0, 4);
        int i3 = ByteBuffer.wrap(bArr3).getInt(); // Length of encrypted Data
        byte[] bArr4 = new byte[i3];
        System.arraycopy(byteArray, 4100, bArr4, 0, i3);
        System.arraycopy(byteArray, 4100 + i3, bArr2, 0, 128);
        C0289q1 c0289q1 = new C0289q1(bArr2);
        byte[] bArr5 = new byte[i3];
        int i4 = 0;
        int i5 = 0;
        for (i2 = 0; i2 < i3; i2++) {
            i4 = (i4 + 1) & 255;
            byte[] bArr6 = (byte[]) c0289q1.c;
            byte b2 = bArr6[i4];
            i5 = (i5 + (b2 & 255)) & 255;
            bArr6[i4] = bArr6[i5];
            bArr6[i5] = b2;
            bArr5[i2] = (byte) (bArr6[(bArr6[i4] + b2) & 255] ^ bArr4[i2]);
        }
        return ByteBuffer.wrap(bArr5);
    }


...
...
    public C0289q1(byte[] bArr) {   // RC4 Routine
        this.a = 17;
        this.b = bArr;
        this.c = new byte[256];
        for (int i = 0; i < 256; i++) {
            ((byte[]) this.c)[i] = (byte) i;
        }
        int i2 = 0;
        for (int i3 = 0; i3 < 256; i3++) {
            byte[] bArr2 = (byte[]) this.c;
            byte b = bArr2[i3];
            byte[] bArr3 = (byte[]) this.b;
            i2 = (i2 + (b & 255) + (bArr3[i3 % bArr3.length] & 255)) & 255;
            bArr2[i3] = bArr2[i2];
            bArr2[i2] = b;
        }
    }

```

### Full Script to Decrypt sqlite.db

To extract, we will need to extract the key and length of the encrypted data before performing RC4. Decrypting this file would allow us to place this in Jadx for further analysis.

```python
class RC4:
    def __init__(self, key):
        self.S = list(range(256))
        self.key = key
        self.key_length = len(key)
        self.i = 0
        self.j = 0
        self._ksa()

    def _ksa(self):
        j = 0
        for i in range(256):
            j = (j + self.S[i] + self.key[i % self.key_length]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]

    def crypt(self, data):
        result = bytearray()
        for byte in data:
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            K = self.S[(self.S[self.i] + self.S[self.j]) % 256]
            result.append(byte ^ K)
        return result

def K(file_data):
    # Read 4 bytes from offset 0x1000 (4096)
    arr_b3 = file_data[0x1000:0x1000 + 4]
    v2 = int.from_bytes(arr_b3, byteorder='big')
    
    # Read v2 bytes from offset 4100
    arr_b4 = file_data[4100:4100 + v2]
    
    # Read 128 bytes from offset 4100 + v2
    arr_b2 = file_data[4100 + v2: 4100 + v2 + 128]
    if len(arr_b2) != 128:
        raise ValueError("Key length is not 128 bytes")
    
    # Initialize RC4 cipher with the key
    rc4 = RC4(arr_b2)
    
    # Decrypt the data
    arr_b5 = rc4.crypt(arr_b4)
    
    return arr_b5


# Read the encrypted file into a byte array
with open('sqlite.db', 'rb') as f:
    file_data = f.read()

# Decrypt the data
decrypted_data = K(file_data)

# Use the decrypted data as needed
print(decrypted_data)

f = open("decrypted_sqlite.db","wb")
f.write(decrypted_data)
f.close()
```

### Quick Check
Opening the decrypted file shows that it is indeed a DEX file, and we see references to the `Storage` class and hints of a `libnative.so` file.

![[Pasted image 20241111155805.png]]
## Message Polling

Decompiling the decrypted `sqlite.db` reveals two messages that are polled from the `Storage` class. By supplying these messages in the `MainActivity`, we can generate the native library libnative.so (Message: `I am a tomb`) and run the native method (Message: `Only Advance`). Monitoring logs with `adb logcat | Select-String TISC` helps find relevant messages.

The two messages are:
- `I am a tomb`
```
10-20 06:35:45.385  6944  6958 I TISC    : Tomb message received!
10-20 06:35:45.584  6944  6958 I TISC    : Native library loaded!
```
- `Only Advance`

```
10-20 06:40:11.801  6944  6958 I TISC    : Advance message received!
10-20 06:40:11.802  6944  6958 D TISC    : There are walls ahead that you'll need to face. They have been specially designed to always result in an
error. One false move and you won't be able to get the desired result. Are you able to patch your way out of this mess?
10-20 06:40:11.802  6944  6958 E TISC    : I need a very specific file to be available. Or do I?
10-20 06:40:11.803  6944  6958 E TISC    : HAHAHA are you sure you've got the right input parameter?
10-20 06:40:11.803  6944  6958 D TISC    : Bet you can't fix the correct constant :)
10-20 06:40:11.803  6944  6958 E TISC    : I'm afraid I'm going to have to stop you from getting the correct key and IV.
10-20 06:40:11.803  6944  6958 E TISC    : Not like this...
10-20 06:40:11.803  6944  6958 D TISC    : The key is: z?<NKKf7m?MUg&>qBp"b9G$A!bzP&0I(
10-20 06:40:11.803  6944  6958 D TISC    : The IV is: apI3`ipq.?3d!t#6
```

### Decompilation of Decrypted `sqlite.db`
We can see the message polling implementation in the following:

```java
package defpackage;
...
...

/* loaded from: C:\Users\user\Desktop\TISC2024\wallfacer\wallfacer-x86_64.apk_Decompiler.com\resources\assets\decrypted_sqlite.db */
public class DynamicClass {
    static final /* synthetic */ boolean $assertionsDisabled = false;
    private static final String TAG = "TISC";

    public static native void nativeMethod();

    public static void dynamicMethod(Context context) throws Exception {
        pollForTombMessage();
        Log.i(TAG, "Tomb message received!");
        File generateNativeLibrary = generateNativeLibrary(context);
        try {
            System.load(generateNativeLibrary.getAbsolutePath());
        } catch (Throwable th) {
            String message = th.getMessage();
            message.getClass();
            Log.e(TAG, message);
            System.exit(-1);
        }
        Log.i(TAG, "Native library loaded!");
        if (generateNativeLibrary.exists()) {
            generateNativeLibrary.delete();
        }
        pollForAdvanceMessage();
        Log.i(TAG, "Advance message received!");
        nativeMethod();
    }

    private static void pollForTombMessage() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> cls;
        do {
            SystemClock.sleep(1000L);
            cls = Class.forName("com.wall.facer.Storage");
        } while (!DynamicClass$$ExternalSyntheticBackport1.m((String) cls.getMethod("getMessage", new Class[0]).invoke(cls.getMethod("getInstance", new Class[0]).invoke(null, new Object[0]), new Object[0]), "I am a tomb"));
    }

    private static void pollForAdvanceMessage() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<?> cls;
        do {
            SystemClock.sleep(1000L);
            cls = Class.forName("com.wall.facer.Storage");
        } while (!DynamicClass$$ExternalSyntheticBackport1.m((String) cls.getMethod("getMessage", new Class[0]).invoke(cls.getMethod("getInstance", new Class[0]).invoke(null, new Object[0]), new Object[0]), "Only Advance"));
    }

    ...
    ...
}
```

## Generating `libnative.so`

The challenge requires generating `libnative.so` by decrypting files in the assets/data folder using the password `wallowinpain`.

1. Collect all filenames in the assets/data folder and sort them in ascending order.
![[Pasted image 20241111155824.png]]
2. For each of these files:
    - Extract the salt from the `filename` (after the `$`), appending `==` for Base64 padding.
    - Use the password wallowi`npain to decrypt the file content using `AES-GCM`.
    - Append the decrypted content to reconstruct `libnative.so`.

### Decompilation

```java
public static File generateNativeLibrary(Context context) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException, IOException {
        AssetManager assets = context.getAssets();
        Resources resources = context.getResources();
        
        // dir is base64 encoded "data" which refers to the directory in the assets folder
        String str = new String(Base64.decode(resources.getString(resources.getIdentifier("dir", "string", context.getPackageName())) + "=", 0));
        String[] list = assets.list(str);
        Arrays.sort(list, new Comparator() { // from class: DynamicClass$$ExternalSyntheticLambda3
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                int m;
                m = DynamicClass$$ExternalSyntheticBackport0.m(Integer.parseInt(((String) obj).split("\\$")[0]), Integer.parseInt(((String) obj2).split("\\$")[0]));
                return m;
            }
        });

        // base is base64 encoded "wallowinpain" according to strings.xml
        // wallowinpain is also the key for the decrypting libnative.so
        String str2 = new String(Base64.decode(resources.getString(resources.getIdentifier("base", "string", context.getPackageName())), 0));   
        File file = new File(context.getFilesDir(), "libnative.so");
        Method method = Class.forName("Oa").getMethod("a", byte[].class, String.class, byte[].class);
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        try {
            for (String str3 : list) {
                InputStream open = assets.open(str + str3);
                byte[] readAllBytes = open.readAllBytes();
                open.close();
                fileOutputStream.write((byte[]) method.invoke(null, readAllBytes, str2, Base64.decode(str3.split("\\$")[1] + "==", 8)));
            }
            fileOutputStream.close();
            return file;
        } catch (Throwable th) {
            try {
                fileOutputStream.close();
            } catch (Throwable th2) {
                Throwable.class.getDeclaredMethod("addSuppressed", Throwable.class).invoke(th, th2);
            }
            throw th;
        }
    }


...
...

/* loaded from: classes.dex */
public class Oa {
    public static byte[] a(byte[] bArr, String str, byte[] bArr2) {
        byte[] b = b(str, bArr2);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] bArr3 = new byte[12];
        int length = bArr.length - 12;
        byte[] bArr4 = new byte[length];
        System.arraycopy(bArr, 0, bArr3, 0, 12);
        System.arraycopy(bArr, 12, bArr4, 0, length);
        cipher.init(2, new SecretKeySpec(b, "AES"), new GCMParameterSpec(128, bArr3));
        return cipher.doFinal(bArr4);
    }

    private static byte[] b(String str, byte[] bArr) {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(str.toCharArray(), bArr, 16384, 256)).getEncoded();
    }
}
```

### Full Script to Regenerate `libnative.so`

```java
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
public class NativeLibReconstructor {

    public static void main(String[] args) {
        // path to data files
        String path = "data/";
        String base = "wallowinpain";
        String data_path = "./assets/data/";
        String libnative_so_path = "./assets/libnative.so";


        // open output stream of libnative_so
        FileOutputStream libnative_so = null;
        try {
            libnative_so = new FileOutputStream(libnative_so_path);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        // enumerate teh files present in data path 
        File folder = new File(data_path);
        File[] listOfFiles = folder.listFiles();
        Arrays.sort(listOfFiles, new Comparator<File>() {
            public int compare(File f1, File f2) {
                return Long.valueOf(f1.lastModified()).compareTo(f2.lastModified());
            }
        });
        // iterate over the files
        //print out hte filenames
        for( File file : listOfFiles) {

            // Read the file content into encrypted_data_arr_b for decrypt_a
            byte[] encrypted_data_arr_b = null;
            try {
                FileInputStream fileInputStream = new FileInputStream(file);
                encrypted_data_arr_b = new byte[(int) file.length()];
                fileInputStream.read(encrypted_data_arr_b);
                fileInputStream.close();
                
                // split the file name with $ adn print only the parts after the $
                String[] parts = file.getName().split("\\$");
                // for each of that file name after the $, i want to read the content and AES GCM decrypt it
                // just want to print out the file name only after the $
                String resource_filename = parts[1] + "==";
                resource_filename = resource_filename.replace("-", "+").replace("_", "/");
                byte[] decrypted_bytes = null;
                try {
                    decrypted_bytes = decrypt_a(encrypted_data_arr_b, base, Base64.getDecoder().decode(resource_filename));
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }

                // append the decrypted bytes into the libnative_so stream
                try {
                    libnative_so.write(decrypted_bytes);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                // print out the decrypted_bytes first 20 bytes
                System.out.println(new String(decrypted_bytes).substring(0, 20));


            } catch (IOException e) {
                e.printStackTrace();
            }

        }

        //close the libnative_so stream
        try{
            libnative_so.close();
        } catch (IOException e){
            e.printStackTrace();
        }
    }

     public static byte[] decrypt_a(byte[] encrypted_data_arr_b, String s, byte[] arr_b1) throws NoSuchAlgorithmException {
        // catcjh NoSuchAlgorithmException;
        Cipher aesGcmCipher_cipher0 ;
        byte[] cipher_text_arr_b4 = null;
        try{
            
            byte[] secret_key_arr_b2 = generate_secret_key_b(s, arr_b1);
            byte[] iv_arr_b3 = new byte[12];

            int cipher_textlength_v = encrypted_data_arr_b.length - 12;
            cipher_text_arr_b4 = new byte[cipher_textlength_v];
            System.arraycopy(encrypted_data_arr_b, 0, iv_arr_b3, 0, 12);
            System.arraycopy(encrypted_data_arr_b, 12, cipher_text_arr_b4, 0, cipher_textlength_v);
            GCMParameterSpec gCMParameterSpec0 = new GCMParameterSpec(0x80, iv_arr_b3);
            aesGcmCipher_cipher0 = Cipher.getInstance("AES/GCM/NoPadding");
            aesGcmCipher_cipher0.init(2, new SecretKeySpec(secret_key_arr_b2, "AES"), gCMParameterSpec0);
            return aesGcmCipher_cipher0.doFinal(cipher_text_arr_b4);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new byte[0]; // Return an empty byte array in case of an exception
    }

    private static byte[] generate_secret_key_b(String s, byte[] arr_b) {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(s.toCharArray(), arr_b, 0x4000, 0x100)).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return new byte[0]; 
        }
    }
}
```

## Analyzing `NativeMethod` from `libnative.so`

After generating libnative.so, we can verify its contents.

![[Pasted image 20241111155838.png]]

### "I need a very specific file to be available. Or do I?"

The program attempts to open `/sys/wall/facer` using `sys_openat`. Since this file doesn't exist, the syscall fails. To bypass this check, we patch the result of the syscall (eax value to 0).


![[Pasted image 20241111155842.png]]

After patching:

![[Pasted image 20241111155845.png]]

Understanding the jump tables is crucial. By patching the eax value to 0, we pass this stage and proceed with the proper calculation of the IV and Key.

#### Patching the Syscall
Throughout this challenge, we would be dealing with jump tables which pays to keep track especially in the last wall. Let's take a look of how such jump table work here.And how patching out eax value to 0 help us to pass this stage with the proper calculation of IV and Key.

![[Pasted image 20241111155851.png]]

 
## Second Wall
In the second wall, a function checks if a parameter equals `0x539` or `1337`. By default, the parameter is `1`.

```asm
.text:0000000000001F78                 mov     edi, 1          ; unsigned int
.text:0000000000001F7D                 call    sub_3430
```

### Patch 1 to 1337

Before patching:
![[Pasted image 20241111155903.png]]

After patching:
![[Pasted image 20241111155906.png]]

Flow after the patch:

![[Pasted image 20241111155912.png]]

## Third Wall

In the third wall, there is a check for the first parameter to be `0x539`. By tracking the jump table and understanding the control flow, we identify where to patch.

![[Pasted image 20241111155920.png]]

In this wall, there is a check for the first parameter again to see if the value is 1337 or 0x539. To understand the flow, tracking of jump table helps greatly if we are not analyzing this dynamically. Additionally, nearing the jump statement, there are some jump table information that is being stored on the stack which has been illustrated in the leftmost side of the following figure:

![[Pasted image 20241111155924.png]]

### Patching points
We need to ensure the first parameter to the function `sub_35B0` is `0x539`. We patch the code to force the sum to be `0x539`.

#### Wall 3 Patch 1 - Sum to 0x539

Before patching:
![[Pasted image 20241111155928.png]]

After patching:
![[Pasted image 20241111155931.png]]

#### Wall 3 Patch 2 - Compare to 0x539

Before:
![[Pasted image 20241111155945.png]]

After:
![[Pasted image 20241111155941.png]]


### The whole Flow for Third Wall

- First Parameter Check  **(POINT A)**
    - Initially, the first parameter is checked if it is 0x539
    - If it is not, it would not set ecx to 0 which is the index to failure from the jump table **(POINT C)**.
    > **We NEED first parameter to be 0x539** to set ecx to allow us to jump to the next stage of this wall **(POINT B)**.
- Based on the previously initialized stack, we know that the index of the jump table to use is 13. Therefore, we would move to `sub_3779` **(POINT D)**
    - There is then another check once again to see if the first parameter is 0x539. If yes, then set index to zero for the upcoming jump table to jump to `sub_3743` **(POINT E)**.
    - We do not want to go to the other route.
- In `sub_3779`, there is another comparison with the first parameter with the value 0xa13, however, we have determined that the first parameter should be 0x539.   
    - Eventually, we want rcx to be 1 to win. However, we have to make sure that the first parameter should be equal to 0xA13 which we will be patching to 0x539 instead. (POINT F)

![[Pasted image 20241111155951.png]]

## Script for the Patch

```python
import sys
data = None
with open("libnative.so.original", 'rb') as f:
    data = f.read()

buffer = bytearray(data)

# Patch the buffer
patch_dict = {
    0x227B: [0x31, 0xc0],  # return non negative value and xor eax for wall1
    0xf79 : [0x39, 0x05],  # set the value of 1337 for wall2
    0x11e6 : [0x90]*4  + [0x48, 0xC7, 0xC0, 0x39, 0x05, 0x00, 0x00, 0x89, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0x90,0x90,0x90] + [0x90]*4 , # Wall 3,
    0x0BAC : [0x39, 0x05], # for wall 3 this is the constant that we change. and first parameter should already be 1337
}

for addr, values in patch_dict.items():
    for i, value in enumerate(values):
        buffer[addr + i] = value   
        # print the above stateement to show the patching process
        print(f"buffer[{hex(addr + i)}] = {hex(value)}")

# Write the patched buffer to a new file
with open("libnative.so", 'wb') as f:
    f.write(buffer)
```

## Modifying the APK

### Replacing `libnative.so`
In order to flag, I have re-encrypted the `libnative.so` file before rebuilding the APK.

I reversed the action by encrypting the `libnative.so` file into one file instead of splitting using `wallowinpain` and placing back into the data folder with the appropriate file name.

```java
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptNativeLib {
    // Encrypts a file with AES-GCM
    public static void main(String[] args) {
        File file = new File("C:\\Users\\user\\Desktop\\TISC2024\\wallfacer\\wallfacer-x86_64.apk_Decompiler.com\\resources\\decrypt\\final_libnative\\libnative.so");
        String encrypted_libnative = "C:\\Users\\user\\Desktop\\TISC2024\\wallfacer\\wallfacer-x86_64.apk_Decompiler.com\\resources\\decrypt\\final_libnative\\0$aGFoYWhhaGFoYWhhaGFoYQ";
        FileOutputStream encryptedLibnativeStream = null;

        try {
            // Output file stream for encrypted libnative
            encryptedLibnativeStream = new FileOutputStream(encrypted_libnative);
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] plainData = new byte[(int) file.length()];
        try {
            FileInputStream fileInputStream = new FileInputStream(file);
            fileInputStream.read(plainData);
            fileInputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Encrypt with AES GCM
        byte[] encryptedData = null;
        try {
            encryptedData = encrypt_a(plainData, "wallowinpain", "hahahahahahahaha".getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // Write encrypted data to the output file
        try {
            if (encryptedLibnativeStream != null) {
                encryptedLibnativeStream.write(encryptedData);
                encryptedLibnativeStream.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Encryption method using AES-GCM
    public static byte[] encrypt_a(byte[] plainData, String password, byte[] salt) throws NoSuchAlgorithmException {
        Cipher aesGcmCipher;
        byte[] cipherTextWithIv = null;
        try {
            // Generate the secret key
            byte[] secretKeyBytes = generate_secret_key_b(password, salt);
            SecretKeySpec secretKey = new SecretKeySpec(secretKeyBytes, "AES");

            // Generate a random 12-byte IV
            byte[] iv = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);

            // Initialize GCM parameter spec with 128-bit authentication tag length
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

            // Initialize the cipher for encryption
            aesGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
            aesGcmCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            // Perform encryption
            byte[] cipherText = aesGcmCipher.doFinal(plainData);

            // Combine IV and ciphertext
            cipherTextWithIv = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
            System.arraycopy(cipherText, 0, cipherTextWithIv, iv.length, cipherText.length);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherTextWithIv != null ? cipherTextWithIv : new byte[0]; // Return the encrypted data with IV
    }

    // Generate secret key using PBKDF2 with HMAC SHA-256
    private static byte[] generate_secret_key_b(String password, byte[] salt) {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(new PBEKeySpec(password.toCharArray(), salt, 0x4000, 256)).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return new byte[0]; // Return an empty byte array in case of an exception
        }
    }
}
```


### Repackaging
This is the script used to automate the repackaging of APK.

```batch
adb uninstall com.wall.facer

del my-aligned.apk
del my.keystore
del wallfacer-x86_64.apk

java -jar apktool_2.10.0.jar b wallfacer-x86_64
copy wallfacer-x86_64\dist\wallfacer-x86_64.apk .
"C:\Program Files (x86)\Java\jre1.8.0_421\bin\keytool"  -genkey -v -keystore my.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias app
"C:\Users\user\AppData\Local\Android\Sdk\build-tools\35.0.0\zipalign" -p 4 wallfacer-x86_64.apk my-aligned.apk

"C:\Users\user\AppData\Local\Android\Sdk\build-tools\35.0.0\apksigner" sign --ks-key-alias app --ks my.keystore  my-aligned.apk
```

## Retrieving the Flag

Script to automate repackaging:

```
10-21 05:30:42.028 11977 11988 I TISC    : Tomb message received!
10-21 05:30:42.167 11977 11988 I TISC    : Native library loaded!
...
...
10-21 05:30:46.175 11977 11988 I TISC    : Advance message received!
10-21 05:30:46.175 11977 11988 D TISC    : There are walls ahead that you'll need to face. They have been specially
designed to always result in an error. One false move and you won't be able to get the desired result. Are you able to
patch your way out of this mess?
10-21 05:30:46.176 11977 11988 I TISC    : One wall down!
10-21 05:30:46.176 11977 11988 I TISC    : Input verification success!
10-21 05:30:46.176 11977 11988 D TISC    : Bet you can't fix the correct constant :)
10-21 05:30:46.176 11977 11988 I TISC    : I guess it's time to reveal the correct key and IV!
10-21 05:30:46.177 11977 11988 D TISC    : The key is: eU9I93-L9S9Z!:6;:i<9=*=8^JJ748%%
10-21 05:30:46.177 11977 11988 D TISC    : The IV is: R"VY!5Jn7X16`Ik]
```

![[Pasted image 20241111160002.png]]

Switch to the query activity:

```bash
# Get to query 
adb shell am start -n com.wall.facer/.query
```

Entering the key and IV reveals the flag in logcat.

![[Pasted image 20241111160010.png]]

```
10-21 05:33:55.215 11977 11977 D TISC    : Decrypted data: The flag is: TISC{1_4m_y0ur_w4llbr34k3r_!i#Leb}
```

> [!note] Flag
> TISC{1_4m_y0ur_w4llbr34k3r_!i#Leb}

# Conclusion
While there are alternative methods to solve it, such as using memory patching, this write-up showcases the approach I took by directly patching and repackaging the APK. Interestingly, I chanced upon [SpaceRaccoon's Writeup](https://github.com/eugene-lim/tisc-2024-writeup?tab=readme-ov-file#8-wallfacer) on the use of Unicorn Emulation to solve this challenge as well!

---
