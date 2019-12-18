package com.springsecurity.jwt.demo.common.utils.jwt;

import cn.hutool.core.date.DateUtil;
import com.alibaba.fastjson.JSON;
import com.springsecurity.jwt.demo.common.constants.SecurityConstants;
import com.springsecurity.jwt.demo.common.constants.UserConstants;
import com.springsecurity.jwt.demo.common.utils.encrypt.AESUtil;
import com.springsecurity.jwt.demo.common.utils.encrypt.RSAUtil;
import com.springsecurity.jwt.demo.core.exception.BizServiceException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * jwt来生成token和解析token
 */
@Slf4j
public class JwtTokenUtil {
    /**
     * 默认token过期时间1小时 单位 毫秒
     */
    private static long KEEP_ALIVE_TIME = 60 * 60 * 1000L;

    private static final String PATH = "/home/eric/IdeaProjects/keys";

    /**
     * 生成token，过期时间为默认值
     *
     * @param username
     * @param map
     */
    public static String generateToken(String username, Map<String, Object> map) {
        return generateToken(username, map, KEEP_ALIVE_TIME);
    }

    /**
     * 生成token 参数可以是任何业务需求中需要用到的值
     *
     * @param map 业务需要携带又不敏感的一些信息
     * @return
     */
    public static String generateToken(String username, Map<String, Object> map, Long expireTime) {
        return generateToken(username, map, expireTime, null, null);
    }

    /**
     * 生成token 参数可以是任何业务需求中需要用到的值
     *
     * @param map        业务需要携带又不敏感的一些信息
     * @param expireMill 过期时间,毫秒
     * @param publicKey  公钥
     * @param privateKey 私钥
     * @return token
     */
    public static String generateToken(String username, Map<String, Object> map, Long expireMill, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        if (expireMill == null) {
            expireMill = KEEP_ALIVE_TIME;
        }
        SignatureAlgorithm algorithm;
        Key key;
        //密钥及加密算法 普通签名算法
        if (Objects.nonNull(publicKey) && Objects.nonNull(privateKey)) {
            //RSA
            algorithm = SignatureAlgorithm.RS256;
            key = privateKey;
        } else {
            algorithm = SignatureAlgorithm.HS256;
            key = new SecretKeySpec(AESUtil.getSecretKey().getBytes(), algorithm.getJcaName());
        }

        Date nowDate = new Date();
        //过期时间
        Date expireDate = new Date(nowDate.getTime() + expireMill);
        /*
         * iss(Issuser)：代表这个JWT的签发主体；
         * sub(Subject)：代表这个JWT的主体，即它的所有人；
         * aud(Audience)：代表这个JWT的接收对象；
         * exp(Expiration time)：是一个时间戳，代表这个JWT的过期时间；
         * nbf(Not Before)：是一个时间戳，代表这个JWT生效的开始时间，意味着在这个时间之前验证JWT是会失败的；
         * iat(Issued at)：是一个时间戳，代表这个JWT的签发时间；
         * jti(JWT ID)：是JWT的唯一标识。
         */

        //登录成功后设置JWT,添加附加信息
        return Jwts.builder()
                //设置token的信息
                .setClaims(map)
                .setIssuer("eric.he")
                //设置主题
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(expireDate)
                .signWith(algorithm, key).compact();
    }

    /**
     * 解析token
     *
     * @param token
     * @return
     */
    public static boolean validateToken(String token) {
        return validateToken(token, null, null);
    }

    /**
     * 解析token
     *
     * @param token
     * @return
     */
    public static boolean validateToken(String token, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        try {
            parseToken(token, publicKey, privateKey);
        } catch (Exception e) {
            log.error("[token验证失败]", e);
            return false;
        }
        return true;
    }

    /**
     * 校验token
     *
     * @param token
     * @return
     */
    public static Claims parseToken(String token) {
        return parseToken(token, null, null);
    }

    /**
     * 判断token在指定时间内是否刚刚刷新过
     *
     * @param token 原token
     * @param time  指定时间（秒）
     */
    public static boolean tokenRefreshJustBefore(String token, int time) {
        Claims claims = parseToken(token);
        Date created = claims.get(SecurityConstants.TIME_STAMP, Date.class);
        Date refreshDate = new Date();
        //刷新时间在创建时间的指定时间内
        if (refreshDate.after(created) && refreshDate.before(DateUtil.offsetSecond(created, time))) {
            return true;
        }
        return false;
    }

    /**
     * 校验token
     *
     * @param token
     * @param publicKey
     * @param privateKey
     * @return
     */
    public static Claims parseToken(String token, RSAPublicKey publicKey, RSAPrivateKey privateKey) throws ExpiredJwtException {
        Key key;
        if (Objects.nonNull(publicKey) && Objects.nonNull(privateKey)) {
            key = publicKey;
        } else {
            key = new SecretKeySpec(AESUtil.getSecretKey().getBytes(), SignatureAlgorithm.HS256.getJcaName());
        }
        try {
            return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            log.error("[token解析失败] token过期");
            throw e;
        } catch (Exception e) {
            log.error("[token解析失败] ", e);
            throw e;
        }
    }

    /**
     * 解析获取用户主体信息
     *
     * @return
     */
    public static String parseTokenGetUsername(String token) {
        Claims claims = parseToken(token);
        if (claims != null) {
            return claims.getSubject();
        }
        return null;
    }

    /**
     * 验证token是否还有效
     *
     * @param token       客户端传入的token
     * @param userDetails 从数据库中查询出来的用户信息
     */
    public static boolean validateToken(String token, UserDetails userDetails) {
        String username = parseTokenGetUsername(token);
        return userDetails.getUsername().equals(username) && !isTokenExpired(token);
    }

    /**
     * 判断token是否已经失效
     */
    private static boolean isTokenExpired(String token) {
        Date expiredDate = getExpiredDateFromToken(token);
        return expiredDate.before(new Date());
    }

    /**
     * 从token中获取过期时间
     */
    private static Date getExpiredDateFromToken(String token) {
        Claims claims = parseToken(token);
        return claims.getExpiration();
    }

    //从token中获取角色
    public static String getUserRole(String token) {
        log.info("从token中获取角色->" + parseToken(token).get(UserConstants.ROLE_CLAIMS));
        return (String) parseToken(token).get(UserConstants.ROLE_CLAIMS);
    }

    public static void main(String[] args) throws Exception {
        //解密
        hmacDemo();
    }


    public static void rsaDemo() {
        //生成rsa的key
        //生成公私钥文件
        RSAUtil.generateKeysToFile(PATH);

        String publicKey = RSAUtil.readKeyFromFile(PATH + "/publicKey.keystore");
        String privateKey = RSAUtil.readKeyFromFile(PATH + "/privateKey.keystore");

        System.out.println("publicKey：" + publicKey);
        System.out.println("privateKey：" + privateKey);


        RSAPublicKey rsaPublicKey = RSAUtil.readPublicKeyFromString(publicKey);
        RSAPrivateKey rsaPrivateKey = RSAUtil.readPrivateKeyFromString(privateKey);

        Map<String, Object> map = new HashMap<>(4);
        map.put(UserConstants.USER_NAME, "heyong_1988");
        map.put(SecurityConstants.TIME_STAMP, System.currentTimeMillis());

        String generateToken = generateToken("heyong_1988", map, 1000L * 60, rsaPublicKey, rsaPrivateKey);
        System.out.println("generateToken = " + generateToken);

        String sign = "eyJhbGciOiJSUzI1NiJ9.eyJuYW1lIjoiemdkIiwiaXNzIjoiemdkIiwic3ViIjoiYWFhIiwiZXhwIjoxNTYzNDE0NTAxLCJpYXQiOjE1NjMzNTQ1MDEsImFnZSI6IjE4In0.UV1jh0B2H8b58Icn8vBoqsG0M2vaVtJcQ0q8aD1WsAnVlDbBEEXNTM_1_8chuFWvd7GGlpVNSapvfiWD6e5CbnDsYaWx1dg07RHGcV-CbLHCwY03TkLSkDHUbxQVC-lMJdjWkazVY8Mdx_j-3O16VGmVRMy768t-SezQQPPRYNg";

        boolean isValidate = validateToken(generateToken, rsaPublicKey, rsaPrivateKey);
        System.out.println("b = " + isValidate);

        Claims claims = parseToken(sign, rsaPublicKey, rsaPrivateKey);
        System.out.println("getClaims= " + JSON.toJSONString(claims));
        System.out.println("getClaims= " + claims.getSubject());
        System.out.println("name = " + claims.get("name"));
    }


    public static void hmacDemo() {
        Map<String, Object> map = new HashMap<>(4);
        map.put(UserConstants.USER_NAME, "heyong_1988");
        map.put(SecurityConstants.TIME_STAMP, System.currentTimeMillis());

        String generateToken = generateToken("heyong_1988", map, 1000L * 60);
        System.out.println("generateToken = " + generateToken);

        boolean isValidated = validateToken(generateToken);
        System.out.println("isValidated? = " + isValidated);
        Claims claims = parseToken(generateToken);
        System.out.println("getClaims= " + JSON.toJSONString(claims));
        System.out.println("getClaims= " + claims.getSubject());
        System.out.println("getClaims= " + claims.getExpiration().toString());
        System.out.println("name = " + claims.get("name"));

    }
}