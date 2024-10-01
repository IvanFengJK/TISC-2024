# TISC-2024

## Level 1 - Navigating the Digital Labyrinth

![Challenge Description](level-1/description.png)

This is an OSINT challenge. We are given the username `vi_vox223`.

I used the search engine DuckDuckGo and quickly found the Instagram account.

![Search Result](level-1/search.png)

I also checked the account, noting that it had only been recently created and was based in Singapore, which confirmed my suspicion that this account was made solely for the purpose of this CTF.

![Instagram Profile](level-1/instagram.png)

From the Instagram story titled `Discord`, I found three suspicious posts, as shown below:

![Post 1](level-1/post1.png)

![Post 2](level-1/post2.png)

![Post 3](level-1/post3.png)

Essentially, we need to add the Discord bot and change our role to `D0PP3L64N63R`.

Since I am new to Discord, I found some helpful resources: [How to add a bot](https://discordjs.guide/preparations/adding-your-bot-to-servers.html#bot-invite-links) and [How to add a role](https://zapier.com/blog/discord-roles/).

I added both bots to see if there was any difference in their responses, but apparently, it didn’t matter.

Here is how the bots responded when I didn’t have a role:

![Without the role](level-1/no_role.png)

After adding the role, this is how the bot responded:

![With the role](level-1/role.png)

I first used the command `!list` to see all the files. After going through them, the only suspicious file was `Update_030624.eml`.

The content is as follows:

```
Dear Headquarters,

I trust this message reaches you securely. I am writing to provide an update on my current location. I am currently positioned close to the midpoint of the following IDs:

8c1e806a3ca19ff 8c1e806a3c125ff 8c1e806a3ca1bff My location is pinpointed with precision using Uber's cutting-edge geospatial technology, which employs shape-based location triangulation and partitions areas of the Earth into identifiable cells.

To initiate secure communication with me, please adhere to the discreet method we've established. Transmit the identified location's name through the secure communication channel accessible at https://www.linkedin.com/company/the-book-lighthouse

Awaiting your confirmation and further operational directives.

Best regards,

Vivoxanderith
```


By referring to Uber's H3 documentation, we can easily decode the IDs and find the midpoint. I had used H3 in a school project before, so I used the older version, h3-3.7.7.

```python
import h3
   
cell_ids = [    "8c1e806a3ca19ff",    "8c1e806a3c125ff",    "8c1e806a3ca1bff"]

coordinates = [h3.h3_to_geo(h3_address) for h3_address in cell_ids]

mid_lat = sum(coord[0] for coord in coordinates) / len(coordinates)
mid_lon = sum(coord[1] for coord in coordinates) / len(coordinates)

print(f"{mid_lat}, {mid_lon}")
```

By searching on Google Maps, it was easy to identify the location as `Quercia secolare`.

However, visiting the LinkedIn link only led to a profile that didn’t accept messages. Looking through the posts, I found another link to a Telegram bot in one of the posts, as shown below:

![Linkedin Post](level-1/linkedin.png)

By visiting the Telegram bot and sending in the location, the flag was released, as shown below:

![Telegram bot](level-1/telegram.png)

So, the flag is TISC{OS1N7_Cyb3r_InV35t1g4t0r_uAhf3n}.

## Level 2 - Language, Labyrinth and (Graphics)Magick

![Challenge Description](level-2/description.png)

This is an interesting challenge. I would say it is about command injection and remote execution.

It has links to the webpage.

![Website](level-2/website.png)

I realised that I can input natural language into the textbox, and it will generate some instructions to be executed on the server side. It will return the image with a link to `hash.txt`. It looks like this:

![hashtext](level-2/hashtext.png)

For example, if I submit an image, the link will lead me to `http://chals.tisc24.ctf.sg:36183/tmp/53e6c466c509f9d7bf2530b55a12e3d3.txt`. This led me to think about path traversal.

I tried a different image, and it gave me another link like this: `http://chals.tisc24.ctf.sg:36183/tmp/0dc46e3dadb9a3b989a035c596623ac9.txt`.

I was still able to navigate between the two hash text files, but I could not travel out of the `tmp` folder.

So, I decided to experiment with running two commands and see the output.

I tried to run `pwd` and have the output redirected into a file in `tmp` as follows:

![pwd](level-2/pwd.jpg)

And I could navigate to the link `http://chals.tisc24.ctf.sg:36183/tmp/new.txt`.

![new](level-2/newtxt.jpg)

This is exciting because we know that the command runs in `app`, which is a different directory from `tmp`.

So, I tried to run `ls` as follows:

![ls](level-2/ls.jpg)

And I could navigate to the link `http://chals.tisc24.ctf.sg:36183/tmp/try.txt`.

![try](level-2/try.jpg)

This way, I found the `flag.txt`, which is probably the goal.

So, I crafted my payload as follows:

![payload](level-2/payload.png)

And I got the flag.

![flag](level-2/flag.png)

So, the flag is `TISC{h3re_1$_yOuR_prOc3s5eD_im4g3_&mORe}`.

## Level 3 - Digging Up History

This is a forensics challenge. I used the FTK Imager, which you can download [here](https://www.exterro.com/digital-forensics-software/ftk-imager).

![challenge](level-3/description.png)

I first searched for the string `flag` and found that there were some linked files to the path `Documents and Settings\csitfanl\Desktop\flag.txt`, but the file didn't exist.

![link](level-3/link.png)

By looking at the history, it seemed like there was a file called `flag.sus`.

While I was searching through all the folders, I found a group of entries that seemed suspicious.

![entries](level-3/entries.jpg)

I exported the folder `entries` and ran a search using Windows commands.

```
> Get-ChildItem -Path <Path to Folder> -Recurse | Select-String -Pattern "flag.sus" | Select-Object Path -Unique

Path
----
...\entries\8EA5B9296FDF7C32DAA8DD848E74AD83F49B2815
```

Then I found this suspicious file.

Inspecting this file showed that it had a link to an Amazon S3 bucket. So I extracted the link `https://csitfan-chall.s3.amazonaws.com/flag.sus` and downloaded a file.

The file contained a string like this: `VElTQ3t0cnUzXzFudDNybjN0X2gxc3QwcjEzXzg0NDU2MzJwcTc4ZGZuM3N9`, which looked like Base64 encoding.

Using CyberChef or this link `https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=VkVsVFEzdDBjblV6WHpGdWRETnliak4wWDJneGMzUXdjakV6WHpnME5EVTJNekp3Y1RjNFpHWnVNM045`, you will get the flag to be `TISC{tru3_1nt3rn3t_h1st0r13_8445632pq78dfn3s}`.

## Level 4 - AlligatorPay

This is a Web and Reverse Engineering Challenge.

![challenge](level-4/description.png)

The challenge links to a website, which is a checker.

![website](level-4/checker.png)

I tried to use Burp Suite to see how the request was being sent but realized that it would alert "invalid card" without sending any request, which means that the algorithm for the check is done on the client side.

![check](level-4/check.jpg)

I saved the page, and you can see it in the folder.

By searching through it, I found the function for the check.

```javascript
async function parseFile() {
    const fileInput = document.getElementById("fileInput");
    const file = fileInput.files[0];
    if (!file) {
        alert("Please select a file");
        return;
    }

    const arrayBuffer = await file.arrayBuffer();
    const dataView = new DataView(arrayBuffer);

    const signature = getString(dataView, 0, 5);
    if (signature !== "AGPAY") {
        alert("Invalid Card");
        return;
    }
    const version = getString(dataView, 5, 2);
    const encryptionKey = new Uint8Array(arrayBuffer.slice(7, 39));
    const reserved = new Uint8Array(arrayBuffer.slice(39, 49));

    const footerSignature = getString(
        dataView,
        arrayBuffer.byteLength - 22,
        6
    );
    if (footerSignature !== "ENDAGP") {
        alert("Invalid Card");
        return;
    }
    const checksum = new Uint8Array(
        arrayBuffer.slice(arrayBuffer.byteLength - 16, arrayBuffer.byteLength)
    );

    const iv = new Uint8Array(arrayBuffer.slice(49, 65));
    const encryptedData = new Uint8Array(
        arrayBuffer.slice(65, arrayBuffer.byteLength - 22)
    );

    const calculatedChecksum = hexToBytes(
        SparkMD5.ArrayBuffer.hash(new Uint8Array([...iv, ...encryptedData]))
    );

    if (!arrayEquals(calculatedChecksum, checksum)) {
        alert("Invalid Card");
        return;
    }

    const decryptedData = await decryptData(
        encryptedData,
        encryptionKey,
        iv
    );

    const cardNumber = getString(decryptedData, 0, 16);
    const cardExpiryDate = decryptedData.getUint32(20, false);
    const balance = decryptedData.getBigUint64(24, false);

    document.getElementById("cardNumber").textContent =
        formatCardNumber(cardNumber);
    document.getElementById("cardExpiryDate").textContent =
        "VALID THRU " + formatDate(new Date(cardExpiryDate * 1000));
    document.getElementById("balance").textContent =
        "$" + balance.toString();
    console.log(balance);
    if (balance == 313371337) {
        function arrayBufferToBase64(buffer) {
        let binary = "";
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
        }

        const base64CardData = arrayBufferToBase64(arrayBuffer);

        const formData = new FormData();
        formData.append("data", base64CardData);

        try {
        const response = await fetch("submit", {
            method: "POST",
            body: formData,
        });

        const result = await response.json();
        if (result.success) {
            alert(result.success);
        } else {
            alert("Invalid Card");
        }
        } catch (error) {
        alert("Invalid Card");
        }
    }
    }
```

#### Crafting a Valid File

I needed to write a file that passes the above checks. This can be easily done.

Here are the libraries I imported. Their usage will be explained later.
```python
import struct
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
```

#### Signature
The function first checks for the signature. So, I wrote `AGPAY` as the first few bytes.

<div style="display: flex; gap: 20px;">
<div style="flex: 1">

```javascript
const arrayBuffer = await file.arrayBuffer();
const dataView = new DataView(arrayBuffer);

const signature = getString(dataView, 0, 5);
if (signature !== "AGPAY") {
    alert("Invalid Card");
    return;
}
```
</div> <div style="flex: 1">

```python
SIGNATURE = b'AGPAY'
```
</div> </div>

#### Version & Reserved
The script extracts the version and the reserved bytes, but it doesn't have any checks, so I can use any dummy values as placeholders.
<div style="display: flex; gap: 20px;">
<div style="flex: 1">

```javascript
const version = getString(dataView, 5, 2);
const reserved = new Uint8Array(arrayBuffer.slice(39, 49));
```
</div> <div style="flex: 1">

```python
VERSION = os.urandom(2)
RESERVED = os.urandom(10)
```
</div> </div>

#### Footer Signature
The footer signature is also a simple check for exact bytes.

<div style="display: flex; gap: 20px;">
<div style="flex: 1">

```javascript
const footerSignature = getString(
    dataView,
    arrayBuffer.byteLength - 22,
    6
);
if (footerSignature !== "ENDAGP") {
    alert("Invalid Card");
    return;
}
```
</div> <div style="flex: 1">

```python
FOOTER_SIGNATURE = b'ENDAGP'
```
</div> </div>

#### Encryption Key and IV

This is a vulnerability. It extracts the encryption key and IV from the card without checking the validity of the IV or the key. This means that an attacker can use any key or IV to disguise as a legitimate card.

<div style="display: flex; gap: 20px;">
<div style="flex: 1">

```javascript
const encryptionKey = new Uint8Array(arrayBuffer.slice(7, 39));
const iv = new Uint8Array(arrayBuffer.slice(49, 65));
```
</div> <div style="flex: 1">

```python
ENCRYPTIPN_KEY = os.urandom(32)
IV = os.urandom(16)
```
</div> </div>

#### Checksum and Data Decryption
To pass the checksum, we need to reverse engineer the required plaintext data and encrypt it to obtain the correct encrypted data.

The script encrypts the card number, expiry date, and balance. The date and card number values don't matter, but the balance must be equal to `313371337`. The card number just needs to be 16 digits long, and the expiry date looks like it is a Unix timestamp. For simplicity, I used the start of the challenge: 13 September 2100hrs, which is `1726232400`. Note that the card expiry date starts at the 20th byte, not immediately after the card number, which ends at the 16th byte.

<div style="display: flex; gap: 20px;">
<div style="flex: 1">

```javascript
const decryptedData = await decryptData(
        encryptedData,
        encryptionKey,
        iv
    );

const cardNumber = getString(decryptedData, 0, 16);
const cardExpiryDate = decryptedData.getUint32(20, false);
const balance = decryptedData.getBigUint64(24, false);

document.getElementById("cardNumber").textContent =
    formatCardNumber(cardNumber);
document.getElementById("cardExpiryDate").textContent =
    "VALID THRU " + formatDate(new Date(cardExpiryDate * 1000));
document.getElementById("balance").textContent =
    "$" + balance.toString();

console.log(balance);
if (balance == 313371337) 
```
</div> <div style="flex: 1">

```python
card_number = b'1234567890123456'
expiry_date = struct.pack('>I', 1726232400)
balance = struct.pack('>Q', 313371337)

data_to_encrypt = card_number + b'\x00\x00\x00\x00' + expiry_date + balance
```
</div> </div>

I searched for the `decryptData` function and found the encryption scheme used. It is AES in CBC mode. Knowing that, I wrote a standard encryption function in Python using the same scheme.

<div style="display: flex; gap: 20px;">
<div style="flex: 1">

```javascript
async function decryptData(encryptedData, key, iv) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-CBC" },
        false,
        ["decrypt"]
    );
    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: iv },
        cryptoKey,
        encryptedData
    );
    return new DataView(decryptedBuffer);
}
```
</div> <div style="flex: 1">

```python
padded_data = pad(data_to_encrypt, AES.block_size)
cipher = AES.new(ENCRYPTIPN_KEY, AES.MODE_CBC, IV)
encrypted_data = cipher.encrypt(padded_data)
```
</div> </div>

The checksum is also found, which is a simple MD5 hash.

```javascript
const calculatedChecksum = hexToBytes(
        SparkMD5.ArrayBuffer.hash(new Uint8Array([...iv, ...encryptedData]))
    );
```
</div> <div style="flex: 1">

```python
checksum = hashlib.md5(iv + encrypted_data).digest()
```
</div> </div>

#### Putting everything together

```python
import struct
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

SIGNATURE = b'AGPAY'
FOOTER_SIGNATURE = b'ENDAGP'
VERSION = os.urandom(2)
RESERVED = os.urandom(10)
ENCRYPTIPN_KEY = os.urandom(32)
IV = os.urandom(16)

card_number = b'1234567890123456'
expiry_date = struct.pack('>I', 1726232400)  # Example: 2025-01-01
balance = struct.pack('>Q', 313371337)

data_to_encrypt = card_number + b'\x00\x00\x00\x00' + expiry_date + balance
padded_data = pad(data_to_encrypt, AES.block_size)

cipher = AES.new(ENCRYPTIPN_KEY, AES.MODE_CBC, IV)
encrypted_data = cipher.encrypt(padded_data)

checksum = hashlib.md5(IV + encrypted_data).digest()

card_data = (
    SIGNATURE +
    VERSION +
    ENCRYPTIPN_KEY +
    RESERVED +  
    IV +
    encrypted_data +
    FOOTER_SIGNATURE +
    checksum
)

with open('custom_card.agp', 'wb') as f:
    f.write(card_data)
```

By submitting the `custom_card.agp`, it will return the flag: `TISC{533_Y4_L4T3R_4LL1G4T0R_a8515a1f7004dbf7d5f704b7305cdc5d}`.