import org.apache.commons.io.FileUtils;
import org.apache.tools.ant.DirectoryScanner;
import org.xmlpull.v1.XmlPullParserException;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.DataFlowResult;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.InfoflowConfiguration.ImplicitFlowMode;
import soot.jimple.infoflow.InfoflowConfiguration.StaticFieldTrackingMode;

import java.io.*;
import java.util.HashSet;
import java.util.Iterator;

public class FlowDroidSpec {
    public String androidJarsPath; // Path to the folder that contains all the Android Jars files, see the README.md
    public String androidAPKsPath; // Path to the folder that contains all the Android .apk files, benign and malign
    public String jcePath; // Optional: Update this variable if the jce.jar file are not found
    public String rtPath; // Optional: Update this variable if the rt.jar file are not found

    HashSet<String> benignSources;
    HashSet<String> benignSinks;
    HashSet<String> malignSources;
    HashSet<String> malignSinks;

    String resourcesPath = System.getProperty("user.dir") + File.separator + "src" +
            File.separator + "test" + File.separator + "resources" + File.separator;

    public FlowDroidSpec(String androidJarsPath, String androidAPKsPath, String jcePath, String rtPath) {
        this.androidJarsPath = androidJarsPath;
        this.androidAPKsPath = androidAPKsPath;
        this.jcePath = jcePath;
        this.rtPath = rtPath;
    }

    public InfoflowResults analyzeAPK(String fileName) throws IOException, XmlPullParserException {
        return analyzeAPK(fileName, false, true, false);
    }

    public InfoflowResults analyzeAPK(String fileName, boolean enableImplicitFlows, boolean enableStaticFields,
                                      boolean flowSensitiveAliasing) throws XmlPullParserException, IOException {
        if (androidJarsPath == null || androidJarsPath.isEmpty()) {
            androidJarsPath = System.getenv("ANDROID_JARS");
            if (androidJarsPath == null)
                androidJarsPath = System.getProperty("ANDROID_JARS");
            if (androidJarsPath == null)
                throw new RuntimeException("Android JAR dir not set");
        }

        SetupApplication setupApplication;
        // The fileName is the full path to the apk
        if (androidAPKsPath == null || androidAPKsPath.isEmpty()) {
            setupApplication = new SetupApplication(androidJarsPath, fileName);
        } else {
            if (androidAPKsPath.isEmpty()) {
                System.out.println("Error: Wrong  apk file name");
                return null;
            }

            DirectoryScanner scanner = new DirectoryScanner();
            scanner.setIncludes(new String[]{"**/" + fileName+ "*.apk"});
            scanner.setBasedir(androidAPKsPath);
            scanner.setCaseSensitive(false);
            scanner.scan();

            if (scanner.getIncludedFiles().length == 0) {
                System.out.println("Error: Apk file not found, check the file name and try again.");
                return null;
            }

            setupApplication = new SetupApplication(androidJarsPath, androidAPKsPath + File.separator + scanner.getIncludedFiles()[0]);
        }

        // Find the taint wrapper file or load from .jar resources
        File taintWrapperFile = new File("EasyTaintWrapperSource.txt");
        if (!taintWrapperFile.exists()) {
            InputStream in = getClass().getResourceAsStream("/EasyTaintWrapperSource.txt");
            FileUtils.copyInputStreamToFile(in, taintWrapperFile);
        }

        setupApplication.setTaintWrapper(new EasyTaintWrapper(taintWrapperFile));

        // Configure the analysis
        setupApplication.getConfig().setImplicitFlowMode(
                enableImplicitFlows ? ImplicitFlowMode.AllImplicitFlows : ImplicitFlowMode.NoImplicitFlows);
        setupApplication.getConfig().setStaticFieldTrackingMode(
                enableStaticFields ? StaticFieldTrackingMode.ContextFlowSensitive : StaticFieldTrackingMode.None);
        setupApplication.getConfig().setFlowSensitiveAliasing(flowSensitiveAliasing);
        // setupApplication.getConfig().setEnableLineNumbers(true);

        if (jcePath == null || jcePath.isEmpty()) {
            jcePath = System.getProperty("java.home") +
                    File.separator + "lib" + File.separator + "jce.jar";

        }

        if (rtPath == null || rtPath.isEmpty()){
            rtPath =
                    System.getProperty("java.home") + File.separator + "lib" + File.separator + "rt.jar";

        }
        setupApplication.getConfig().getAnalysisFileConfig().setAdditionalClasspath(jcePath + File.pathSeparator + rtPath);
        setupApplication.getConfig().setOneComponentAtATime(true);
        setupApplication.getConfig().getPathConfiguration().setPathReconstructionMode(InfoflowConfiguration.PathReconstructionMode.Precise);
        setupApplication.getConfig().getPathConfiguration().setPathReconstructionTimeout(1000);

        // Find the source and sink file or load from the .jar resources
        File SourceAndSinkFile = new File("SourcesAndSinks.txt");
        if (!SourceAndSinkFile.exists()) {

            InputStream in = getClass().getResourceAsStream("/SourcesAndSinks.txt");
            FileUtils.copyInputStreamToFile(in, SourceAndSinkFile);

        }
        return setupApplication.runInfoflow("SourcesAndSinks.txt");
    }

    public int numberOfConflicts(InfoflowResults appVersionResults) {
        if (appVersionResults == null)
            return 0;

        return appVersionResults.getResultSet() == null ? 0 : appVersionResults.getResultSet().size();
    }

    public int reportConflicts(InfoflowResults benignResults, InfoflowResults malignResults) {
        if (numberOfConflicts(malignResults) == 0)
            return 0;

        if (numberOfConflicts(benignResults) == 0)
            return numberOfConflicts(malignResults);

        int conflicts = 0;
        if (malignResults.getResultSet() != null) {
            for (DataFlowResult malignResult : malignResults.getResultSet()) {

                boolean isAValidConflict = true;
                if (benignResults.getResultSet() != null) {
                    for (DataFlowResult benignResult : benignResults.getResultSet()) {
                        // The conflict is invalid if are in both versions of app
                        if (malignResult.toString().equals(benignResult.toString())) {
                            isAValidConflict = false;
                        }
                    }
                }

                if (isAValidConflict) {
                    conflicts++;
                }
            }
        }

        return conflicts;
    }

    public String getParformaceData(InfoflowResults appVersionResults) {
        if (appVersionResults == null)
            return "Empty";

        if (appVersionResults.getPerformanceData() == null)
            return "Empty";

        return appVersionResults.getPerformanceData().toString();
    }

    public void exportResultsData(String fileName, InfoflowResults benignResults, InfoflowResults malignResults, int conflicts) {
        benignSources = new HashSet<String>();
        benignSinks = new HashSet<String>();
        malignSources = new HashSet<String>();
        malignSinks = new HashSet<String>();

        try {
            FileWriter Writer = new FileWriter(resourcesPath + File.separator + "exportedData"
                    + File.separator + fileName + ".txt");

            Writer.write(fileName + " results data. " + '\n');
            Writer.write('\n');

            Writer.write("Found " + conflicts + " conflicts." + '\n');
            Writer.write('\n');

            if (benignResults != null) {
                if (benignResults.getResultSet() != null) {
                    for (DataFlowResult benignResult : benignResults.getResultSet()) {
                        benignSources.add(benignResult.getSource().toString());
                        benignSinks.add(benignResult.getSink().toString());
                    }
                }

                Writer.write("Benign: " + '\n');
                Writer.write("Number of conflicts: " + numberOfConflicts(benignResults) + '\n');
                Writer.write("Number of sources: " + benignSources.size() + '\n');
                Writer.write("Number of sinks: " + benignSinks.size() + '\n');
                Writer.write("Performance data: " + getParformaceData(benignResults) + '\n');

                Writer.write("List of Sources: " + '\n');
                Iterator<String> it =  benignSources.iterator();
                while(it.hasNext()) {
                    Writer.write("\t" + it.next() + '\n');
                }


                Writer.write("List of Sinks: " + '\n');
                it =  benignSinks.iterator();
                while(it.hasNext()) {
                    Writer.write("\t" + it.next() + '\n');
                }
                Writer.write('\n');
            }

            if (malignResults != null) {
                if (malignResults.getResultSet() != null) {
                    for (DataFlowResult malignResult : malignResults.getResultSet()) {
                        malignSources.add(malignResult.getSource().toString());
                        malignSinks.add(malignResult.getSink().toString());
                    }
                }

                Writer.write("Malign: " + '\n');
                Writer.write("Number of conflicts: " + numberOfConflicts(malignResults) + '\n');
                Writer.write("Number of sources: " + malignSources.size() + '\n');
                Writer.write("Number of sinks: " + malignSinks.size() + '\n');
                Writer.write("Performance data: " + getParformaceData(malignResults) + '\n');

                Writer.write("List of Sources: " + '\n');
                Iterator<String> it =  malignSources.iterator();
                while(it.hasNext()) {
                    Writer.write("\t" + it.next() + '\n');
                }
                Writer.write('\n');

                Writer.write("List of Sinks: " + '\n');
                it =  malignSinks.iterator();
                while(it.hasNext()) {
                    Writer.write("\t" + it.next() + '\n');
                }
                Writer.write('\n');
            }

            Writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred when exporting the results data of the app: " + fileName);
            e.printStackTrace();
        }
    }

}
