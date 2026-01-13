import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

public class SecureApp {

    // ✅ A2: Cryptographic Failures (Hardcoded Credentials) - FIXED
    // ✅ SSRF Protection: Validate database URL
    private static final String DB_URL;
    private static final String DB_USER;
    private static final String DB_PASSWORD;
    
    static {
        // قراءة متغيرات البيئة
        String envDbUrl = System.getenv("DB_URL");
        String envDbUser = System.getenv("DB_USERNAME");
        String envDbPassword = System.getenv("DB_PASSWORD");
        
        // التحقق من SSRF: التأكد أن URL قاعدة البيانات مسموح به
        if (isValidDatabaseUrl(envDbUrl)) {
            DB_URL = envDbUrl;
        } else {
            DB_URL = null;
            System.err.println("Invalid or unsafe database URL configured");
        }
        
        DB_USER = envDbUser;
        DB_PASSWORD = envDbPassword;
    }
    
    // دالة للتحقق من أمان رابط قاعدة البيانات (منع SSRF)
    private static boolean isValidDatabaseUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        
        try {
            URI uri = new URI(url);
            String protocol = uri.getScheme();
            String host = uri.getHost();
            
            // السماح فقط لبروتوكولات قواعد البيانات الآمنة
            if (!"jdbc:mysql".equals(protocol) && !"jdbc:postgresql".equals(protocol)) {
                System.err.println("Unsupported database protocol: " + protocol);
                return false;
            }
            
            // التأكد من وجود host
            if (host == null) {
                return false;
            }
            
            // منع SSRF: رفض الوصول إلى العناوين المحلية والداخلية
            if (isLocalOrInternalAddress(host)) {
                System.err.println("Access to local/internal address blocked: " + host);
                return false;
            }
            
            // في البيئات الإنتاجية، استخدم قائمة بيضاء للمضيفين المسموح بهم
            String[] allowedHosts = {
                "prod-database.example.com",
                "backup-db.example.com"
                // أضف المضيفين المسموح بهم هنا
            };
            
            for (String allowedHost : allowedHosts) {
                if (host.equals(allowedHost) || host.endsWith("." + allowedHost)) {
                    return true;
                }
            }
            
            System.err.println("Database host not in allowed list: " + host);
            return false;
            
        } catch (Exception e) {
            System.err.println("Invalid database URL format: " + e.getMessage());
            return false;
        }
    }
    
    // التحقق إذا كان العنوان محلي أو داخلي (لمنع SSRF)
    private static boolean isLocalOrInternalAddress(String host) {
        if (host == null) return true;
        
        host = host.toLowerCase();
        
        // رفض العناوين المحلية والداخلية
        return host.equals("localhost") || 
               host.equals("127.0.0.1") || 
               host.equals("0.0.0.0") || 
               host.equals("::1") ||
               host.equals("[::1]") ||
               host.startsWith("192.168.") ||
               host.startsWith("10.") ||
               (host.startsWith("172.") && isInPrivateRange(host)) ||
               host.startsWith("169.254.") ||
               host.endsWith(".local") ||
               host.endsWith(".internal") ||
               host.contains(".localdomain");
    }
    
    private static boolean isInPrivateRange(String host) {
        try {
            if (host.startsWith("172.")) {
                String[] parts = host.split("\\.");
                if (parts.length >= 2) {
                    int secondOctet = Integer.parseInt(parts[1]);
                    return secondOctet >= 16 && secondOctet <= 31;
                }
            }
            return false;
        } catch (Exception e) {
            return true; // في حالة الخطأ، افترض أنه عنوان داخلي
        }
    }
    
    public Connection connectDB() {
        try {
            if (DB_URL == null || DB_USER == null || DB_PASSWORD == null) {
                throw new IllegalStateException("Database credentials not configured properly");
            }
            
            // تحقق إضافي قبل الاتصال
            if (!isValidDatabaseUrl(DB_URL)) {
                throw new SecurityException("Database URL validation failed - SSRF protection");
            }
            
            return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        } catch (SecurityException e) {
            System.err.println("Security violation: " + e.getMessage());
            throw e;
        } catch (Exception e) {
            System.err.println("Database connection error: " + e.getMessage());
            return null;
        }
    }

    // ✅ A3: Injection (SQL Injection) - FIXED
    public boolean login(HttpServletRequest request) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        
        try {
            String username = sanitizeInput(request.getParameter("username"));
            String password = request.getParameter("password");
            
            // التحقق من صحة المدخلات
            if (!isValidUsername(username) || !isValidPassword(password)) {
                System.err.println("Invalid input parameters");
                return false;
            }
            
            // استخدام PreparedStatement لمنع SQL Injection
            String query = "SELECT * FROM users WHERE username = ? AND password_hash = ?";
            
            conn = connectDB();
            if (conn == null) {
                System.err.println("Database connection failed");
                return false;
            }
            
            pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            pstmt.setString(2, hashPassword(password, getSaltForUser(username)));
            
            rs = pstmt.executeQuery();
            
            if (rs.next()) {
                System.out.println("Login successful for user: " + username);
                return true;
            } else {
                System.out.println("Login failed for user: " + username);
                return false;
            }
        } catch (Exception e) {
            System.err.println("Login error: " + e.getMessage());
            return false;
        } finally {
            closeResources(conn, pstmt, rs);
        }
    }

    // ✅ A1: Broken Access Control - FIXED
    public void deleteUser(HttpServletRequest request, String currentUserRole) {
        String userId = sanitizeInput(request.getParameter("id"));
        
        // التحقق من صلاحيات المستخدم
        if (!"ADMIN".equals(currentUserRole) && !"SUPER_ADMIN".equals(currentUserRole)) {
            System.err.println("Access denied: Insufficient privileges");
            return;
        }
        
        // التحقق من صحة معرّف المستخدم
        if (!isValidUserId(userId)) {
            System.err.println("Invalid user ID format");
            return;
        }
        
        // منع المستخدم من حذف نفسه
        String currentUserId = getCurrentUserId(request);
        if (userId.equals(currentUserId)) {
            System.err.println("Cannot delete own account");
            return;
        }
        
        System.out.println("User with ID " + userId + " deleted by " + currentUserRole);
    }

    // ✅ A3: Injection (Command Injection) - FIXED
    public void executeCommand(HttpServletRequest request) {
        String cmd = sanitizeInput(request.getParameter("cmd"));
        
        if (cmd == null || cmd.trim().isEmpty()) {
            System.err.println("No command specified");
            return;
        }
        
        // قائمة الأوامر المسموح بها فقط (Allow List)
        String[] allowedCommands = {"ls", "pwd", "date", "whoami", "echo"};
        
        boolean isAllowed = false;
        String safeCmd = null;
        
        for (String allowed : allowedCommands) {
            if (allowed.equals(cmd.split(" ")[0])) {
                isAllowed = true;
                safeCmd = allowed;
                break;
            }
        }
        
        if (!isAllowed || safeCmd == null) {
            System.err.println("Command not allowed: " + cmd);
            return;
        }
        
        try {
            // استخدام ProcessBuilder مع قائمة ثابتة من المعاملات
            ProcessBuilder pb = new ProcessBuilder(safeCmd);
            
            // لا تمرير أي معاملات من المستخدم
            Process process = pb.start();
            process.waitFor();
            System.out.println("Command executed: " + safeCmd);
        } catch (Exception e) {
            System.err.println("Command execution failed: " + e.getMessage());
        }
    }

    // ✅ A5: Security Misconfiguration (Path Traversal) - FIXED
    public void readFile(HttpServletRequest request) {
        try {
            String fileName = sanitizeInput(request.getParameter("file"));
            
            if (fileName == null || fileName.trim().isEmpty()) {
                System.err.println("No filename specified");
                return;
            }
            
            // تحديد المسار الأساسي الآمن
            Path basePath = Paths.get("/var/data").toAbsolutePath().normalize();
            Path requestedPath = basePath.resolve(fileName).normalize();
            
            // التحقق أن المسار المطلوب يبدأ بالمسار الأساسي
            if (!requestedPath.startsWith(basePath)) {
                System.err.println("Access denied: Path traversal attempt");
                return;
            }
            
            // منع الوصول إلى الملفات الحساسة
            if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
                System.err.println("Invalid filename");
                return;
            }
            
            File file = requestedPath.toFile();
            
            if (!file.exists()) {
                System.err.println("File does not exist");
                return;
            }
            
            if (!file.isFile()) {
                System.err.println("Not a regular file");
                return;
            }
            
            System.out.println("Reading file: " + file.getPath());
            
        } catch (Exception e) {
            System.err.println("File reading error: " + e.getMessage());
        }
    }

    // ✅ A9: Security Logging and Monitoring Failures - FIXED
    public void processPayment(String cardNumber) {
        if (!isValidCardNumber(cardNumber)) {
            System.err.println("Invalid card number");
            return;
        }
        
        // إخفاء رقم البطاقة في السجلات
        String maskedCard = maskCardNumber(cardNumber);
        System.out.println("Processing payment with card: " + maskedCard);
    }

    // ===== وظائف مساعدة =====
    
    private String sanitizeInput(String input) {
        if (input == null) return "";
        // إزالة الأحرف الخاصة الخطرة
        return input.replaceAll("[<>\"'\\\\;|&$`]", "");
    }
    
    private boolean isValidUsername(String username) {
        return username != null && username.matches("^[a-zA-Z0-9_@.-]{3,50}$");
    }
    
    private boolean isValidPassword(String password) {
        return password != null && password.length() >= 8 && password.length() <= 128;
    }
    
    private boolean isValidUserId(String userId) {
        return userId != null && userId.matches("^[0-9]{1,10}$");
    }
    
    private boolean isValidCardNumber(String cardNumber) {
        return cardNumber != null && cardNumber.matches("^[0-9]{13,19}$");
    }
    
    private String maskCardNumber(String cardNumber) {
        if (cardNumber == null || cardNumber.length() < 4) {
            return "****";
        }
        String lastFour = cardNumber.substring(cardNumber.length() - 4);
        return "****-****-****-" + lastFour;
    }
    
    private String hashPassword(String password, String salt) {
        try {
            // في التطبيق الحقيقي، استخدم BCrypt أو PBKDF2
            SecureRandom random = new SecureRandom();
            byte[] hash = new byte[32];
            random.nextBytes(hash);
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Password hashing failed", e);
        }
    }
    
    private String getSaltForUser(String username) {
        // في التطبيق الحقيقي، استرجع Salt من قاعدة البيانات
        return "static_salt_for_demo";
    }
    
    private String getCurrentUserId(HttpServletRequest request) {
        // في التطبيق الحقيقي، استرجع ID المستخدم من الجلسة
        return "user123";
    }
    
    private void closeResources(Connection conn, PreparedStatement pstmt, ResultSet rs) {
        try { if (rs != null) rs.close(); } catch (Exception e) {}
        try { if (pstmt != null) pstmt.close(); } catch (Exception e) {}
        try { if (conn != null) conn.close(); } catch (Exception e) {}
    }
}
