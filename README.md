# XJWT
 

This is a reference implementation of XJWT in Java, a simplified and more secure variation of the original JWT standard.  XJWT spec can be found at https://github.com/ilab-x/hep/blob/master/manual/jwt.md .

Contributions for other languages are welcome.

## Java Key size exception

If you encounter the key size exception, here is an excellent explaination and how to resolve this issue:


"On a default JDK installation, AES is limited to 128 bit key size. In order to perform 256-bit AES encryption, you will need to download and install Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files. Here are the steps to fix java.security.InvalidKeyException: Illegal key size exception:

1.  Go to Oracle’s website and search for ‘Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files’.
2. Depending upon the Java version installed on your machine, download the zip file and extract it on your drive.
3. From the extracted folder, copy local_policy.jar and US_export_policy.jar files.
4. Go to your_java_installation_directory/jre/lib/security and paste the copied files. These files will already be there, you just need to copy and replace. "


https://deveshsharmablogs.wordpress.com/2012/10/09/fixing-java-security-invalidkeyexception-illegal-key-size-exception/
