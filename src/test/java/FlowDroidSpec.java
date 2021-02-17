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
    public String androidJarsPath; 
    public String androidAPKsPath; 

    String resourcesPath = System.getProperty("user.dir") + File.separator + "src" +
            File.separator + "test" + File.separator + "resources" + File.separator;

    public FlowDroidSpec(String androidJarsPath, String androidAPKsPath) {
        this.androidJarsPath = androidJarsPath;
        this.androidAPKsPath = androidAPKsPath;
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
        if (androidAPKsPath == null || androidAPKsPath.isEmpty()) {
            setupApplication = new SetupApplication(androidJarsPath, fileName);
        } else {
            DirectoryScanner scanner = new DirectoryScanner();
            scanner.setIncludes(new String[]{"**/" + fileName+ "*.apk"});
            scanner.setBasedir(androidAPKsPath);
            scanner.setCaseSensitive(false);
            scanner.scan();

            setupApplication = new SetupApplication(androidJarsPath, androidAPKsPath + File.separator + scanner.getIncludedFiles()[0]);
        }

        File taintWrapperFile = new File("EasyTaintWrapperSource.txt");
        if (!taintWrapperFile.exists()) {
            InputStream in = getClass().getResourceAsStream("/EasyTaintWrapperSource.txt");
            FileUtils.copyInputStreamToFile(in, taintWrapperFile);
        }

        setupApplication.setTaintWrapper(new EasyTaintWrapper(taintWrapperFile));

        setupApplication.getConfig().setImplicitFlowMode(
                enableImplicitFlows ? ImplicitFlowMode.AllImplicitFlows : ImplicitFlowMode.NoImplicitFlows);
        setupApplication.getConfig().setStaticFieldTrackingMode(
                enableStaticFields ? StaticFieldTrackingMode.ContextFlowSensitive : StaticFieldTrackingMode.None);
        setupApplication.getConfig().setFlowSensitiveAliasing(flowSensitiveAliasing);
        setupApplication.getConfig().setEnableLineNumbers(true);

        jcePath = System.getProperty("java.home") + File.separator + "lib" + File.separator + "jce.jar";
        rtPath = System.getProperty("java.home") + File.separator + "lib" + File.separator + "rt.jar";

        setupApplication.getConfig().getAnalysisFileConfig().setAdditionalClasspath(jcePath + File.pathSeparator + rtPath);
        setupApplication.getConfig().setOneComponentAtATime(true);
        setupApplication.getConfig().getPathConfiguration().setPathReconstructionMode(InfoflowConfiguration.PathReconstructionMode.Precise);
        setupApplication.getConfig().getPathConfiguration().setPathReconstructionTimeout(1000);

        File SourceAndSinkFile = new File("SourcesAndSinks.txt");
        if (!SourceAndSinkFile.exists()) {

            InputStream in = getClass().getResourceAsStream("/SourcesAndSinks.txt");
            FileUtils.copyInputStreamToFile(in, SourceAndSinkFile);

        }
        return setupApplication.runInfoflow("SourcesAndSinks.txt");
    }

    public int reportConflicts(InfoflowResults benignResults, InfoflowResults malignResults) {
        if (benignResults != null) {
            System.out.println("Benign: ");
            int benignConflicts = benignResults.getResultSet() == null ? 0 : benignResults.getResultSet().size();
            System.out.println("Number of conflicts: " + benignConflicts);
            System.out.println("Performance data: " + benignResults.getParformaceData().toString() + '\n');
        }

        if (malignResults != null) {
            System.out.println("Malign: ");
            int malignConflicts = malignResults.getResultSet() == null ? 0 : malignResults.getResultSet().size();
            System.out.println("Number of conflicts: " + malignConflicts);
            System.out.println("Performance data: " + malignResults.getParformaceData().toString() + '\n');
        }

        if (malignResults == null || malignResults.getResultSet() == null || malignResults.getResultSet().size() == 0) {
            return 0;
        }

        if (benignResults == null || benignResults.getResultSet() == null || benignResults.getResultSet().size() == 0) {
            return malignResults.getResultSet() == null || malignResults.getResultSet().size();
        }

        int conflicts = 0;
        if (malignResults.getResultSet() != null) {
            for (DataFlowResult malignResult : malignResults.getResultSet()) {

                boolean detected = false;
                if (benignResults.getResultSet() != null) {
                    for (DataFlowResult benignResult : benignResults.getResultSet()) {
                        if (malignResult.toString().equals(benignResult.toString())) {
                            detected = true;
                        }
                    }
                }

                if (detected == false) {
                    conflicts++;
                }
            }
        }

        return conflicts;
    }
}
