import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import java.io.File;

public class OWASP_Vulnerable_App {

    // 🔴 A2: Cryptographic Failures (Hardcoded Credentials)
    public Connection connectDB() {
        try {
            return DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/appdb",
                "admin",
                "admin123"
            );
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // 🔴 A3: Injection (SQL Injection)
    public void login(HttpServletRequest request) {
        try {
            String username = request.getParameter("username");
            String password = request.getParameter("password");

            String query = "SELECT * FROM users WHERE username = '"
                    + username + "' AND password = '" + password + "'";

            Connection conn = connectDB();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                System.out.println("Login successful");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 🔴 A1: Broken Access Control
    public void deleteUser(HttpServletRequest request) {
        String userId = request.getParameter("id");
        // لا يوجد تحقق من صلاحيات المستخدم
        System.out.println("User with ID " + userId + " deleted");
    }

    // 🔴 A3: Injection (Command Injection)
    public void executeCommand(HttpServletRequest request) {
        try {
            String cmd = request.getParameter("cmd");
            Runtime.getRuntime().exec(cmd);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 🔴 A5: Security Misconfiguration (Path Traversal)
    public void readFile(HttpServletRequest request) {
        try {
            String fileName = request.getParameter("file");
            File file = new File("/var/data/" + fileName);
            System.out.println("Reading file: " + file.getPath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 🔴 A9: Security Logging and Monitoring Failures
    public void processPayment(String cardNumber) {
        // تسجيل بيانات حساسة بدون حماية
        System.out.println("Processing card: " + cardNumber);
    }
}
