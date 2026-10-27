/*!40101 SET @OLD_CHARACTER_SET_CLIENT = @@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES ascii */;
/*!40014 SET FOREIGN_KEY_CHECKS = 0 */;


-- Dumping structure for table dns.blob
CREATE TABLE IF NOT EXISTS `blob` (
  `sha1` BINARY(20) NOT NULL,
  `blob` BLOB       NOT NULL,
  PRIMARY KEY (`sha1`)
)
  ENGINE =InnoDB
  DEFAULT CHARSET =ascii
  COLLATE =ascii_bin;


-- Dumping structure for table dns.blacklist
CREATE TABLE IF NOT EXISTS `blacklist` (
  `ip` VARBINARY(16) NOT NULL,
--  `reason` TINYINT(3) UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`ip`)
)
  ENGINE =InnoDB
  DEFAULT CHARSET =ascii
  COLLATE =ascii_bin;


-- Dumping structure for table dns.packet
CREATE TABLE IF NOT EXISTS `packet` (
  `id`               BIGINT(20) UNSIGNED  NOT NULL AUTO_INCREMENT,
  `source`           VARBINARY(16)        NULL,
  `source_port`      SMALLINT(6) UNSIGNED NOT NULL DEFAULT 0,
  `destination`      VARBINARY(16)        NULL,
  `destination_port` SMALLINT(6) UNSIGNED NOT NULL DEFAULT 53,
  `txnid`            INT(10) UNSIGNED     NOT NULL,
  `qr`               BIT(1),
  `opcode`           BIT(4),
  `aa`               BIT(1),
  `tc`               BIT(1),
  `rd`               BIT(1),
  `z`                BIT(3),
  `rcode`            BIT(4),
  `qdcount`          SMALLINT(6) UNSIGNED NOT NULL,
  `ancount`          SMALLINT(6) UNSIGNED NOT NULL,
  `nscount`          SMALLINT(6) UNSIGNED NOT NULL,
  `arcount`          SMALLINT(6) UNSIGNED NOT NULL,
  `suffix`           BINARY(20)           NULL,
  `questionset`      BINARY(20)           NOT NULL,
  `recordset`        BINARY(20)           NOT NULL,
  `effective_ttl`    INT(10) UNSIGNED     NOT NULL DEFAULT 0, -- SELECT MIN(ttl) from packet_record WHERE packet=id
  `cached`           TIMESTAMP            NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `source` (`source`),
  KEY `destination` (`destination`),
  KEY `questionset` (`questionset`),
  KEY `recordset` (`recordset`)
)
  ENGINE =InnoDB
  DEFAULT CHARSET =ascii
  COLLATE =ascii_bin;


-- Dumping structure for table dns.names
CREATE TABLE IF NOT EXISTS `name` (
  `id`     BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `parent` BIGINT(20) UNSIGNED DEFAULT NULL,
  `name`   VARCHAR(64)         NOT NULL,
  PRIMARY KEY (`id`),
  KEY `parent` (`parent`),
  KEY `name` (`name`)
)
  ENGINE =InnoDB
  DEFAULT CHARSET =ascii
  COLLATE =ascii_general_ci;


-- Dumping structure for table dns.question
CREATE TABLE IF NOT EXISTS resource_header (
  `id`    BIGINT(20) UNSIGNED  NOT NULL AUTO_INCREMENT,
  `name`  BIGINT(20) UNSIGNED  NOT NULL,
  `type`  SMALLINT(5) UNSIGNED NOT NULL,
  `class` SMALLINT(5) UNSIGNED NOT NULL,
  PRIMARY KEY (`id`),
  KEY `name` (`name`),
  CONSTRAINT `rh_name_fk` FOREIGN KEY (`name`) REFERENCES `name` (`id`)
)
  ENGINE =InnoDB;


--  Dumping structure for table dns.record
CREATE TABLE IF NOT EXISTS `resource_record` (
  `id`     BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `header` BIGINT(20) UNSIGNED NOT NULL,
  `rdata`  BINARY(20)          NOT NULL,
  PRIMARY KEY (`id`),
  KEY `resource_header` (`header`),
  KEY `rdata` (`rdata`),
  CONSTRAINT `rr_header_fk` FOREIGN KEY (`header`) REFERENCES `resource_header` (`id`),
  CONSTRAINT `rr_rdata_fk` FOREIGN KEY (`rdata`) REFERENCES `blob` (`sha1`)
)
  ENGINE =InnoDB
  DEFAULT CHARSET =ascii
  COLLATE =ascii_bin;

-- Dumping structure for table dns.packet_question
CREATE TABLE IF NOT EXISTS `packet_question` (
  `id`              BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, -- shouldn't/can't depend on INSERT default SORT BY order...
  `packet`          BIGINT(20) UNSIGNED NOT NULL,
  `resource_header`        BIGINT(20) UNSIGNED NOT NULL,
  `compressed_name` TINYBLOB            NULL,
  PRIMARY KEY (`id`),
  KEY `packet` (`packet`),
  KEY `resource_header` (`resource_header`),
  CONSTRAINT `packet_question_packet_fk` FOREIGN KEY (`packet`) REFERENCES `packet` (`id`),
  CONSTRAINT `packet_question_rh_fk` FOREIGN KEY (`resource_header`) REFERENCES `resource_header` (`id`)
)
  ENGINE =InnoDB;


-- Dumping structure for table dns.query
CREATE TABLE IF NOT EXISTS `query` (
  `packet`     BIGINT(20) UNSIGNED NOT NULL,
  `parent`     BIGINT(20) UNSIGNED NULL,
  `nameserver` BIGINT(20) UNSIGNED NULL,
  `address`    BIGINT(20) UNSIGNED NULL,
-- TODO: consider "multiple response" case, as well as TC
  `response`   BIGINT(20) UNSIGNED NULL,
  PRIMARY KEY (`packet`),
  KEY `parent` (`parent`),
  KEY `nameserver` (`nameserver`),
  KEY `address` (`address`),
  KEY `response` (`response`),
--  CONSTRAINT `query_parent_fk` FOREIGN KEY (`parent`) REFERENCES `query` (`id`),
  CONSTRAINT `query_packet_fk` FOREIGN KEY (`packet`) REFERENCES `packet` (`id`),
  CONSTRAINT `query_nameserver_fk` FOREIGN KEY (`nameserver`) REFERENCES resource_record (`id`),
  CONSTRAINT `query_address_fk` FOREIGN KEY (`address`) REFERENCES resource_record (`id`),
  CONSTRAINT `query_response_fk` FOREIGN KEY (`response`) REFERENCES `packet` (`id`)
)
  ENGINE =InnoDB;


-- Dumping structure for table dns.packet_record
CREATE TABLE IF NOT EXISTS `packet_record` (
  `id`               BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, -- shouldn't/can't depend on INSERT default SORT BY order...
  `packet`           BIGINT(20) UNSIGNED NOT NULL,
  `record`           BIGINT(20) UNSIGNED NOT NULL, -- TODO: should be 'uncompressed, and in canonical name form'
-- TODO: Might be nice to have a field for the over-the-wire bytes of a given name VARCHAR(255)/blob_id?
-- RFC2181 suggests ttl be "ignored" when considering record sets, log as part of the packet instead of the record
  `compressed_name`  TINYBLOB            NULL,
  `compressed_rdata` BINARY(20)          NULL,
  `ttl`              INT(10) UNSIGNED    NOT NULL,
  PRIMARY KEY (`id`),
  KEY `packet` (`packet`),
  KEY `record` (`record`),
  CONSTRAINT `packet_record_packet_fk` FOREIGN KEY (`packet`) REFERENCES `packet` (`id`),
  CONSTRAINT `packet_record_record_fk` FOREIGN KEY (`record`) REFERENCES resource_record (`id`)
)
  ENGINE =InnoDB;


/*!40014 SET FOREIGN_KEY_CHECKS = 1 */;
/*!40101 SET CHARACTER_SET_CLIENT = @OLD_CHARACTER_SET_CLIENT */;
