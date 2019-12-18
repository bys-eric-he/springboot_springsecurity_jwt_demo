package com.springsecurity.jwt.demo.web.config;

import com.baomidou.mybatisplus.enums.IdType;
import com.baomidou.mybatisplus.generator.AutoGenerator;
import com.baomidou.mybatisplus.generator.config.DataSourceConfig;
import com.baomidou.mybatisplus.generator.config.GlobalConfig;
import com.baomidou.mybatisplus.generator.config.PackageConfig;
import com.baomidou.mybatisplus.generator.config.StrategyConfig;
import com.baomidou.mybatisplus.generator.config.rules.DbType;
import com.baomidou.mybatisplus.generator.config.rules.NamingStrategy;

import java.util.ResourceBundle;

/**
 * mybatis 逆向工程
 */
public class MysqlGenerator {

    public static void main(String[] args) {
        // 代码生成器
        AutoGenerator mpg = new AutoGenerator();

        ResourceBundle rs = ResourceBundle.getBundle("Mybatis-Plus");

        // 全局配置
        GlobalConfig gc = new GlobalConfig();
        String projectPath = System.getProperty("user.dir");
        String outputPath = projectPath + "/src/main/java";

        //outputDir：生成文件的输出目录，默认值：D 盘根目录
        gc.setOutputDir(outputPath);
        //IdType设置主键生成策略，默认值null
        gc.setIdType(IdType.AUTO);
        //Author设置作者
        gc.setAuthor(rs.getString("author"));
        //Open：是否打开输出目录
        gc.setOpen(false);
        //覆盖替换同名文件
        gc.setFileOverride(true);
        // 开启 activeRecord 模式
        gc.setActiveRecord(true);
        // XML 二级缓存
        gc.setEnableCache(false);
        // XML ResultMap
        gc.setBaseResultMap(true);
        // XML columList
        gc.setBaseColumnList(true);

        mpg.setGlobalConfig(gc);

        // 数据源配置
        DataSourceConfig dsc = new DataSourceConfig();
        dsc.setUrl("jdbc:mysql://"+rs.getString("host")+":"+rs.getString("port")
                +"/"+rs.getString("databaseName")+"?serverTimezone=UTC&amp&characterEncoding=utf8&useSSL=false");
        dsc.setDriverName("com.mysql.cj.jdbc.Driver");
        dsc.setUsername(rs.getString("username"));
        dsc.setPassword(rs.getString("password"));
        //设置数据库类型，默认MYSQL
        dsc.setDbType(DbType.MYSQL);
        mpg.setDataSource(dsc);

        // 包配置
        PackageConfig pc = new PackageConfig();
        pc.setController("controller");
        pc.setEntity("model");
        pc.setMapper("mapper");
        pc.setXml("mapper");
        pc.setService("service");
        pc.setServiceImpl("service.impl");
        //父包名。如果为空，将下面子包名必须写全部， 否则就只需写子包名
        pc.setParent(rs.getString("package"));
        mpg.setPackageInfo(pc);

        //模板配置

        // 策略配置
        StrategyConfig strategy = new StrategyConfig();
        //设置命名格式
        strategy.setNaming(NamingStrategy.underline_to_camel);
        //【实体】是否为lombok模型（默认 false）
        strategy.setEntityLombokModel(true);
        //生成 @RestController 控制器
        strategy.setRestControllerStyle(true);
        // 需要生成的具体的表
        if (rs.containsKey("tableName")) {
            strategy.setInclude(rs.getString("tableName").split(","));
        }
        //驼峰转连字符
        strategy.setControllerMappingHyphenStyle(true);
        //表名前缀
        strategy.setTablePrefix(rs.getString("tablePrefix"));
        //是否生成实体时，生成字段注解
        strategy.entityTableFieldAnnotationEnable(true);
        //设置自定义继承的Entity类全称，带包名
        //strategy.setSuperEntityClass("com.lj.common.BaseEntit");
        //设置自定义继承的Controller类全称，带包名
        //strategy.setSuperControllerClass("com.lj.common.BaseController");
        //设置自定义基础的Entity类，公共字段
        //strategy.setSuperEntityColumns("id");
        mpg.setStrategy(strategy);
        mpg.execute();
    }
}