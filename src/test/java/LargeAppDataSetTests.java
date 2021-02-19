import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.xmlpull.v1.XmlPullParserException;
import soot.jimple.infoflow.results.InfoflowResults;

import java.io.File;
import java.io.IOException;

public class LargeAppDataSetTests {
    String resourcesPath = System.getProperty("user.dir") + File.separator + "src" +
            File.separator + "test" + File.separator + "resources" + File.separator;
    String androidJarsPath =  resourcesPath + "androidJARs";
    String androidAPKsPath = resourcesPath + "androidAPKs";

    @Test
    public void runTestApp1() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-1-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-1-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp2() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-2-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-2-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp3() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-3-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-3-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp4() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-4-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-4-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp5() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-5-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-5-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp6() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-6-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-6-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp7() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-7-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-7-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp8() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-8-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-8-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp9() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-9-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-9-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp10() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-10-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-10-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp11() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-11-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-11-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp12() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-12-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-12-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp13() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-13-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-13-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp14() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-14-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-14-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp15() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-15-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-15-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp16() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-16-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-16-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp17() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-17-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-17-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp18() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-18-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-18-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp19() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-19-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-19-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp20() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-20-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-20-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp21() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-21-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-21-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    // This test case require that 2 Android classes should be added in the initializeSoot() method
    // in the SetupApplication class, but this method is private and can not be overridden. We test
    // this app with a modified version of the SetupApplication class and the result was:
    //
    //
    //
    // The 2 lines below are the classes that should be added in the initializeSoot() method, just
    // before the Scene.v().loadNecessaryClasses(); line
    //
	// Scene.v().addBasicClass("android.app.Service", HIERARCHY);
	// Scene.v().addBasicClass("android.webkit.WebView", HIERARCHY);
    @Ignore
    public void runTestApp22() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-22-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-22-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp23() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-23-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-23-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp24() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-24-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-24-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    // Should remove this test
    @Ignore
    public void runTestApp25() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-25-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-25-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp26() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-26-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-26-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp27() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-27-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-27-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp28() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-28-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-28-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp29() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-29-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-29-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp30() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-30-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-30-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp31() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-31-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-31-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp32() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-32-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-32-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp33() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-33-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-33-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp34() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-34-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-34-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp35() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-35-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-35-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    // Should remove this test
    @Ignore
    public void runTestApp36() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-36-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-36-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp37() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-37-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-37-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp38() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-38-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-38-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp39() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-39-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-39-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp40() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-40-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-40-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp41() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-41-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-41-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp42() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-42-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-42-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp43() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-43-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-43-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp44() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-44-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-44-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp45() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-45-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-45-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp46() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-46-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-46-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp47() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-47-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-47-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp48() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-48-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-48-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp49() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-49-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-49-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp50() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-50-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-50-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp51() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-51-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-51-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp52() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-52-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-52-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp53() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-53-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-53-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp54() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-54-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-54-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp55() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-55-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-55-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp56() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-56-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-56-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp57() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-57-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-57-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp58() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-58-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-58-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp59() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-59-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-59-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp60() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-60-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-60-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp61() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-61-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-61-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp62() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-62-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-62-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp63() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-63-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-63-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp64() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-64-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-64-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp65() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-65-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-65-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp66() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-66-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-66-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp67() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-67-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-67-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp68() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-68-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-68-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp69() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-69-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-69-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp70() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-70-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-70-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp71() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-71-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-71-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp72() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-72-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-72-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp73() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-73-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-73-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp74() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-74-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-74-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp75() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-75-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-75-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp76() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-76-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-76-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp77() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-77-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-77-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp78() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-78-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-78-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp79() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-79-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-79-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp80() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-80-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-80-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp81() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-81-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-81-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp82() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-82-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-82-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp83() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-83-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-83-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp84() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-84-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-84-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp85() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-85-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-85-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp86() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-86-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-86-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp87() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-87-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-87-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    // Should remove this test
    @Ignore
    public void runTestApp88() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-88-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-88-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp89() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-89-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-89-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp90() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-90-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-90-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp91() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-91-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-91-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp92() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-92-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-92-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    // Should remove this test
    @Ignore
    public void runTestApp93() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-93-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-93-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    // This test case require that 2 Android classes should be added in the initializeSoot() method
    // in the SetupApplication class, but this method is private and can not be overridden. We test
    // this app with a modified version of the SetupApplication class and the result was:
    //
    //
    //
    // The 2 lines below are the classes that should be added in the initializeSoot() method, just
    // before the Scene.v().loadNecessaryClasses(); line
    //
    // Scene.v().addBasicClass("android.app.Service", HIERARCHY);
    // Scene.v().addBasicClass("android.webkit.WebView", HIERARCHY);
    @Ignore
    public void runTestApp94() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-94-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-94-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp95() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-95-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-95-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp96() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-96-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-96-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp97() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-97-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-97-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp98() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-98-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-98-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp99() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-99-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-99-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp100() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-100-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-100-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp101() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-101-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-101-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }

    @Test
    public void runTestApp102() throws XmlPullParserException, IOException {
        FlowDroidSpec analyzer = new FlowDroidSpec(androidJarsPath, androidAPKsPath);
        InfoflowResults benignResults = analyzer.analyzeAPK("benign-app-102-", false, false, false);
        InfoflowResults malignResults = analyzer.analyzeAPK("malicious-app-102-", false, false, false);

        int conflicts = analyzer.reportConflicts(benignResults, malignResults);

        System.out.println("Found " + conflicts + " conflicts.");
        Assert.assertTrue(conflicts > 0);
    }
}
