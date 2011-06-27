# Makefile for building glusterfs hadoop jar
# XXX: temprory makefile - used during development only

JAVAC=javac
HADOOP_VER=0.20.2
CLASSFILE_DIR=./ghadoop/

HADOOP_CORE_JAR=~/hdfs/hadoop-$(HADOOP_VER)/hadoop-$(HADOOP_VER)-core.jar
JAVAC_OPTS=-Xlint:deprecation -classpath $(HADOOP_CORE_JAR) -d $(CLASSFILE_DIR)

GLUSTERFS_JAVA_SOURCE=../GlusterFileSystem.java
GLUSTERFS_JAVA_SOURCE_DEPS=../*.java
GLUSTERFS_JAR=glusterfs-3.2.0.jar

jar:
	mkdir $(CLASSFILE_DIR)
	$(JAVAC) $(JAVAC_OPTS) $(GLUSTERFS_JAVA_SOURCE_DEPS) $(GLUSTERFS_JAVA_SOURCE)
	if [ $$? -eq 0 ] ; then cd $(CLASSFILE_DIR) && jar cvf ../$(GLUSTERFS_JAR) . ; fi
	rm -rf $(CLASSFILE_DIR)