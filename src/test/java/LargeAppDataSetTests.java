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
}
