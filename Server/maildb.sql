-- MySQL dump 10.13  Distrib 5.6.21, for Win64 (x86_64)
--
-- Host: localhost    Database: maildb
-- ------------------------------------------------------
-- Server version	5.6.21

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `tbl_mails`
--
create database maildb;
use maildb;
DROP TABLE IF EXISTS `tbl_mails`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tbl_mails` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `sender` varchar(256) NOT NULL,
  `recipient` varchar(256) NOT NULL,
  `body` longtext,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=49 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tbl_mails`
--

LOCK TABLES `tbl_mails` WRITE;
/*!40000 ALTER TABLE `tbl_mails` DISABLE KEYS */;
INSERT INTO `tbl_mails` VALUES (41,'2020-08-23 06:26:28','alice','bob','\nHi bob,\n\nWe will meeting on 9.00 am. Do you join?\n\nBest regards,\nAlice.'),(42,'2020-08-23 06:32:00','bob','alice','\nHi Alice,\nI\'m busy on the morning. Do you change the meeting to the afternoon?\nThank you.\nBob'),(43,'2020-08-23 06:35:25','alice','bob','\nOK.\nPlease prepare for your presentation!\nBest regards,\nAlice.\n'),(44,'2020-08-23 06:42:24','bob','alice','\nDear Alice,\nWho does come to my meeting?\nI will try my best.\nThank you.\n'),(45,'2020-08-23 06:44:59','alice','bob','\nDear Bob,\nOur Director board will join. So your presentation is very important.\nBe strong!\nBest regards,\nAlice.'),(46,'2020-08-23 06:47:21','alice','bob','\nDear Bob,\nCongratulation! Yor presentation was awsome.\nBest regards,\nAlice.\n'),(47,'2020-08-23 06:51:19','charlie','bob','\nHi Bob,\nYou\'re crazy.\nWell done!\nCharlie.'),(48,'2020-08-23 06:52:57','bob','charlie','\nHi Charlie,\nI don\'t believe that I\'ve done.\n:)\n');
/*!40000 ALTER TABLE `tbl_mails` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-08-24  9:59:56
