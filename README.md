# DroidXP Taint Analysis Tests
This repository holds all taint analysis test cases and results of the DroidXP paper.

## Dependencies and Setup
The required dependencies:
- Java 8
- Maven  
- FlowDroid
- Android Jar files
- Android Apk files

### Java and Maven
The process to install Java and Maven change with the system. The system used in the tests was the Elementary OS 5.1, a distro linux based in the Ubuntu 18.04. To install the Java 8 and Maven in this system, just need to run command below.
```shell
sudo apt-get update && sudo apt-get install openjdk-8-jdk maven
```

### FlowDroid
The FlowDroid version used in this project was 2.8 and can be got in [secure-software-engineering/FlowDroid](https://github.com/secure-software-engineering/FlowDroid/releases/tag/v2.8) repository at GitHub. We recommend using the `soot-infoflow-cmd-jar-with-dependencies.jar` file because already have all dependencies of FlowDroid and is easy to configure with Maven using the command below.

```shell
mvn install:install-file -Dfile=<path-to-soot-infoflow-cmd-with-dependencies.jar> \
  -DgroupId=de.tud.sse \
  -DartifactId=soot-infoflow-cmd \
  -Dversion=2.8 \
  -Dpackaging=jar
```

### Android Jar files
The FlowDroid uses a set of Android Jar files for the analysis. This files can be gotten in [Sable/android-platforms](https://github.com/Sable/android-platforms) repository at GitHub. Just clone the repository at the `src/test/resources/androidJARs` or set the `ANDROID_JARS` environment variable to the path of the folder in your system command line.

### Android APKs
To run the test cases, you will need the set of apks used in the tests, enter in contact to more information about it. If you already have the set of apks, just need place then in the `src/test/resources/androidAPKs` folder. The test cases are configured to use regular expressions to find the apks, for the benign version of the app the pattern of the name was `benign-app-<app_number>-*.apk`. Make sure that the apks names follow the pattern or you will need to set the full path of the apk in the test case. The pattern used for the malign version of the app was `malicious-app-<app_number>-*.apk`, the same rules to the benign version are applied to malign version.

## Run
To execute all the test cases you can use maven or IDE of choice. 

### Using Maven
```shell
mvn -Dtest=LargeAppDataSetTests test
```

## Results
In the `src/test/resources/exportedData` folder are the files that contains all the data of the last execution of test cases with number of conflicts, sources and sinks of both versions of the apk, the number if valid conflicts (conflits in the malign version of the app that are not present in the benign version), sources and sinks of the both versions of app and performance related data of the analysis (when available).

- Number of test cases: 102
- Ignored test cases: 6 (See details in the LargeAppDataSetTests.java)
- Tests passed: 62
- Test Failed: 34


### List of apps with undetected conflicts
- app-4
- app-5
- app-7
- app-10
- app-11
- app-15
- app-20
- app-27
- app-28
- app-31
- app-34
- app-39
- app-47
- app-48
- app-49
- app-53
- app-60
- app-63
- app-64
- app-65
- app-68
- app-69
- app-70
- app-75
- app-79
- app-81
- app-85
- app-86
- app-89
- app-91
- app-96
- app-97
- app-99
- app-102