package com.zhangwei.epinv.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

public class JwtUtils {

    private static final long EXPIRE_TIME = 5*60*1000;

    public static final String AUTH_HEADER = "X-Authorization-With";

    public static final String SECRET = "abcd";

    public static String sign(String username,String secret){
        Date expireDate = new Date(System.currentTimeMillis()+EXPIRE_TIME);
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withClaim("username",username)
                    .withExpiresAt(expireDate)
                    .sign(algorithm);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verify(String token,String username,String secret){
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier jwtVerifier = JWT.require(algorithm).withClaim("username",username).build();
            jwtVerifier.verify(token);
            return true;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static String getClaimField(String token,String field){
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getClaim(field).asString();
    }

    public static boolean isTokenExpired(String token){
        Date now = Calendar.getInstance().getTime();
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getExpiresAt().before(now);
    }

    public static String refreshTokenExpired(String token,String secret){
        DecodedJWT jwt = JWT.decode(token);
        Map<String, Claim> claimMap = jwt.getClaims();
        Date expireDate = new Date(System.currentTimeMillis()+EXPIRE_TIME);
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTCreator.Builder builder =  JWT.create().withExpiresAt(expireDate);
            for(Map.Entry<String,Claim> entry : claimMap.entrySet()){
                builder.withClaim(entry.getKey(),entry.getValue().asString());
            }
            return builder.sign(algorithm);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }
}
