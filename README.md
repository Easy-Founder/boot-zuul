# boot-zuul

### 启动脚本
```
-Xms512m -Xmx512m -XX:+HeapDumpOnOutOfMemoryError -XX:+PrintTenuringDistribution -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintGCCause -XX:+UseGCLogFileRotation -XX:NumberOfGCLogFiles=5 -XX:GCLogFileSize=1m -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=256m -Xloggc:logs/gc-%t-%p.log

nohup java -Xms512m -Xmx512m -XX:MetaspaceSize=256m -XX:MaxMetaspaceSize=256m -XX:+HeapDumpOnOutOfMemoryError -XX:+PrintTenuringDistribution -Xloggc:logs/gc-%t-%p.log -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintGCCause -jar boot-zuul-0.0.1-SNAPSHOT.jar >> nohup_boot_zuul.log 2>&1 &
```
