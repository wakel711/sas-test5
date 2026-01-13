import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

public class SecureApp {

    // ✅ A2: Cryptographic Failures (Hardcoded Credentials) - FIXED
    // استخدم متغيرات البيئة أو نظام إدارة الأسرار
    private static final String DB_URL = System.getenv("DB_URL");
    private static final String DB_USER = System.getenv("DB_USERNAME");
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    
    public Connection connectDB() {
        try {
            if (DB_URL == null || DB_USER == null || DB_PASSWORD == null) {
                throw new IllegalStateException("Database credentials not configured in environment variables");
            }
            return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // ✅ A3: Injection (SQL Injection) - FIXED
    public void login(HttpServletRequest request) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            String username = sanitizeInput(request.getParameter("username"));
            String password = request.getParameter("password"); // لا يتم تجزئته هنا في هذا المثال البسيط

            // استخدام PreparedStatement لمنع SQL Injection
            String query = "SELECT * FROM users WHERE username = ? AND password = ?";
            
            conn = connectDB();
            if (conn == null) {
                System.err.println("Database connection failed");
                return;
            }
            
            pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            pstmt.setString(2, password); // في الواقع، يجب تخزين hash وليس النص العادي
            rs = pstmt.executeQuery();

            if (rs.next()) {
                System.out.println("Login successful");
            } else {
                System.out.println("Login failed");
            }
        } catch (Exception e) {
            System.err.println("Login error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // إغلاق الموارد
            try { if (rs != null) rs.close(); } catch (Exception e) {}
            try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }

    // ✅ A1: Broken Access Control - FIXED
    public void deleteUser(HttpServletRequest request, String currentUserRole) {
        String userId = sanitizeInput(request.getParameter("id"));
        
        // التحقق من صلاحيات المستخدم
        if (!"ADMIN".equals(currentUserRole)) {
            System.err.println("Access denied: User does not have ADMIN role");
            return;
        }
        
        // التحقق من صحة معرّف المستخدم
        if (!isValidUserId(userId)) {
            System.err.println("Invalid user ID");
            return;
        }
        
        System.out.println("User with ID " + userId + " deleted by ADMIN");
        // تنفيذ عملية الحذف الحقيقية هنا
    }

    // ✅ A3: Injection (Command Injection) - FIXED
    public void executeCommand(HttpServletRequest request) {
        String cmd = sanitizeInput(request.getParameter("cmd"));
        
        // قائمة الأوامر المسموح بها فقط (Allow List)
        String[] allowedCommands = {"ls", "pwd", "date", "whoami"};
        
        boolean isAllowed = false;
        for (String allowed : allowedCommands) {
            if (allowed.equals(cmd)) {
                isAllowed = true;
                break;
            }
        }
        
        if (!isAllowed) {
            System.err.println("Command not allowed: " + cmd);
            return;
        }
        
        try {
            // استخدام ProcessBuilder بدلاً من Runtime.exec للحماية الأفضل
            ProcessBuilder pb = new ProcessBuilder();
            
            // تقسيم الأمر إلى أجزاء لمنع الحقن
            if (cmd.contains(" ")) {
                String[] parts = cmd.split(" ");
                pb.command(parts);
            } else {
                pb.command(cmd);
            }
            
            Process process = pb.start();
            process.waitFor();
            System.out.println("Command executed: " + cmd);
        } catch (Exception e) {
            System.err.println("Command execution failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ✅ A5: Security Misconfiguration (Path Traversal) - FIXED
    public void readFile(HttpServletRequest request) {
        try {
            String fileName = sanitizeInput(request.getParameter("file"));
            
            // تحديد المسار الأساسي الآمن
            Path basePath = Paths.get("/var/data").toAbsolutePath().normalize();
            Path requestedPath = basePath.resolve(fileName).normalize();
            
            // التحقق أن المسار المطلوب يبدأ بالمسار الأساسي (منع Path Traversal)
            if (!requestedPath.startsWith(basePath)) {
                System.err.println("Access denied: Path traversal attempt detected");
                return;
            }
            
            File file = requestedPath.toFile();
            
            // التحقق الإضافي أن الملف موجود وأنه ملف عادي
            if (!file.exists()) {
                System.err.println("File does not exist");
                return;
            }
            
            if (!file.isFile()) {
                System.err.println("Path is not a regular file");
                return;
            }
            
            System.out.println("Reading file: " + file.getPath());
            // قراءة الملف هنا...
            
        } catch (Exception e) {
            System.err.println("File reading error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ✅ A9: Security Logging and Monitoring Failures - FIXED
    public void processPayment(String cardNumber) {
        // التحقق من صحة رقم البطاقة
        if (!isValidCardNumber(cardNumber)) {
            System.err.println("Invalid card number");
            return;
        }
        
        // إخفاء رقم البطاقة في السجلات (إظهار الأرقام الأربعة الأخيرة فقط)
        String maskedCard = maskCardNumber(cardNumber);
        System.out.println("Processing card: " + maskedCard);
        
        // معالجة الدفع هنا...
    }

    // ===== وظائف مساعدة للتحقق من الصحة =====
    
    private String sanitizeInput(String input) {
        if (input == null) return "";
        // إزالة الأحرف الخاصة الخطرة
        return input.replaceAll("[<>\"'\\\\;]", "");
    }
    
    private boolean isValidUserId(String userId) {
        // التحقق أن معرّف المستخدم يحتوي على أرقام فقط
        return userId != null && userId.matches("^[0-9]+$");
    }
    
    private boolean isValidCardNumber(String cardNumber) {
        // التحقق من تنسيق رقم البطاقة (أرقام فقط، 13-19 رقم)
        return cardNumber != null && cardNumber.matches("^[0-9]{13,19}$");
    }
    
    private String maskCardNumber(String cardNumber) {
        if (cardNumber == null || cardNumber.length() < 4) {
            return "****";
        }
        // إظهار الأرقام الأربعة الأخيرة فقط
        String lastFour = cardNumber.substring(cardNumber.length() - 4);
        return "****-****-****-" + lastFour;
    }
    
    // دالة مساعدة للتجزئة الآمنة لكلمات المرور (للحصول على كود آمن تماماً)
    public String hashPassword(String password, String salt) {
        try {
            // استخدام خوارزمية آمنة مثل PBKDF2
            // هذا مثال مبسط - في التطبيق الحقيقي استخدم مكتبة أمنية
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            String saltedPassword = salt + password;
            byte[] hash = md.digest(saltedPassword.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed", e);
        }
    }
    
    public String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
}
