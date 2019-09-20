package com.softtouchit.jwt;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Date;

import jwt.JWT;
import jwt.KEY;
import net.sf.json.JSONObject;


public class TestJWT {

    public static void main(String[] args)
    {
	try
	{
		String data= "";
		// =================示例：解密xjwt (token也是一个xjwt);
		String xjwt = "AAABbUy0XxsCAAAAAAABiDA%3D.xPwVH6y5s7tALHu1W3z4zX9Moo5j3qHhHylUxL2lVFzRKDBzQpK1YmrohX2gKKVE.zxDXPoreJXv8N1BAtMUcceupBM8nf0UcWQx5j0u6Ao0%3D";
		data = dencrty(xjwt);
		System.out.println(data);

		// =================示例：生成xjwt

		JSONObject param=new JSONObject();
		param.put("username","test");
		param.put("issuerId",KEY.issueId.toString());
		String json=param.toString();

		data = encrty(json);
		System.out.println(data);

	} catch (Exception e)
	{
		e.printStackTrace();
	}

    }
    public static String dencrty(String xjwt) throws Exception {
    	//获取当前时间
    	long now = new Date().getTime();
    	//创建JWT实例
        JWT jwt = new JWT(KEY.secret, KEY.aeskey,now,KEY.issueId);
        //对数据进行url 解码
        xjwt=URLDecoder.decode(xjwt,"UTF-8"); 
        //解密数据
        String json = jwt.verifyAndDecrypt(xjwt,  now);
        return json;
    }
    
    public static String encrty(String json) throws Exception {
	//获取当前时间
	long now=System.currentTimeMillis();
	//创建JWT实例
	JWT jwt=new JWT(KEY.secret,KEY.aeskey,now,KEY.issueId);
	//创建payload
	ByteBuffer payload = ByteBuffer.allocate(1024).order(ByteOrder.BIG_ENDIAN);
        payload.put(json.getBytes("UTF-8")).flip();
	//创建out
        ByteBuffer out = ByteBuffer.allocate(1024);
        //加密数据
        jwt.encryptAndSign(JWT.Type.SYS,payload,out,now+60*60*1000);
        String xjwt = new String(out.array(),out.arrayOffset(),out.remaining());
        //对数据进行url 编码
        return URLEncoder.encode(xjwt,"UTF-8");
    }
}
