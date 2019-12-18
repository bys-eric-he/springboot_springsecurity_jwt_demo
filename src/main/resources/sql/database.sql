CREATE DATABASE `spring-security-jwt` DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci;

USE `spring-security-jwt`;

CREATE TABLE `tbl_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `role_name` varchar(255) DEFAULT NULL,
  `create_time` timestamp(6) NULL DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `tbl_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '用户主键',
  `username` varchar(40) NOT NULL DEFAULT 'heyong' COMMENT '用户名',
  `password` varchar(255) NOT NULL DEFAULT '1990' COMMENT '用户密码',
  `remark` varchar(500) NULL COMMENT '备注',
  `status` smallint(2) NOT NULL DEFAULT 0 COMMENT '状态',
  `create_time` datetime NOT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_time` datetime NOT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;

CREATE TABLE `tbl_user_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `role_id` int(11) DEFAULT NULL,
  `create_time` datetime NOT NULL ON UPDATE CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;


select *from `spring-security-jwt`.`tbl_role`;
select *from `spring-security-jwt`.`tbl_user`;
select *from `spring-security-jwt`.`tbl_user_role`;

INSERT INTO `spring-security-jwt`.`tbl_role` (`id`,`role_name`,`create_time`) VALUES (1,'ROLE_ADMIN', '2019-12-10 11:15:49.000000'),(2,'ROLE_USER', '2019-12-10 11:16:04.000000');

INSERT INTO `spring-security-jwt`.`tbl_user` (`id`,`username`,`password`,`create_time`,`update_time`) VALUES (1, 'admin', '$2a$10$.8baftxWLye9qoSsLZCR9OrkCyE/TmBmlc5hWd0xCCWiIb20CuLUe', '2019-12-10 11:59:58','2019-12-10 11:59:58'),(2, 'eric.he', '$2a$10$.8baftxWLye9qoSsLZCR9OrkCyE/TmBmlc5hWd0xCCWiIb20CuLUe', '2019-12-10 11:16:39','2019-12-10 11:59:58'),(3, 'heyong', '$2a$10$mp0UA9FgWDahU0vMGojiAuS862.LG4FFNpAkBy3skEGCyYTeXcEx.', '2019-12-10 11:01:52','2019-12-10 11:59:58'),(4, 'sky', '$2a$10$.8baftxWLye9qoSsLZCR9OrkCyE/TmBmlc5hWd0xCCWiIb20CuLUe', '2019-12-10 10:29:35','2019-12-10 11:59:58'),(5, 'alex', '$2a$10$.8baftxWLye9qoSsLZCR9OrkCyE/TmBmlc5hWd0xCCWiIb20CuLUe', '2019-12-10 10:29:51','2019-12-10 11:59:58');

INSERT INTO `spring-security-jwt`.`tbl_user_role` (`id`,`user_id`,`role_id`,`create_time`) VALUES (1, 1, 1, now()),(2, 1, 1, now()),(3, 2, 2, now()),(4, 4, 1, now()),(5, 5, 2, now());
