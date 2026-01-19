package za.ac.cput.Controller.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import za.ac.cput.Domain.User.Admin;
import za.ac.cput.Domain.User.Applicant;
import za.ac.cput.Domain.bookings.TestAppointment;
import za.ac.cput.Repository.AdminRepository;
import za.ac.cput.Service.impl.AdminService;
import za.ac.cput.Service.jwt.TokenUtil;

import java.util.*;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/admins")
public class AdminController {

    private final AdminService adminService;

    @Autowired
    private TokenUtil tokenUtil;
    @Autowired  // Add this annotation
    private AdminRepository adminRepository;

    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);

    @Autowired
    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    // ✅ GET login page endpoint (public)
    @GetMapping("/login")
    public ResponseEntity<?> loginPage() {
        System.out.println("🔍 ADMIN LOGIN PAGE: Login page accessed");
        return ResponseEntity.ok(Map.of(
                "message", "Admin login page - use POST /admins/login with email and password to authenticate",
                "required_fields", "email, password",
                "email_domain", "@admin.co.za",
                "example", Map.of("email", "admin@admin.co.za", "password", "yourpassword")
        ));
    }

    // Create a new admin (public - no token required)
// Create a new admin (public - no token required)
    @PostMapping("/create")
    public ResponseEntity<?> create(@RequestBody Admin admin) {
        try {
            // --- Basic validations ---
            if (admin.getContact() == null || admin.getContact().getEmail() == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("success", false, "message", "Email is required"));
            }

            String email = admin.getContact().getEmail();

            // Admins must use admin email domain
            if (!email.endsWith("@admin.co.za")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("success", false, "message", "Admins must use @admin.co.za email domain"));
            }

            // --- Create the admin ---
            Admin created = adminService.create(admin);

            // ✅ RETURN CONSISTENT SUCCESS RESPONSE
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of(
                            "success", true,
                            "message", "Admin registered successfully",
                            "data", created
                    ));

        } catch (org.springframework.dao.DataIntegrityViolationException ex) {
            // --- Handle duplicate key errors dynamically ---
            String dbMessage = ex.getMostSpecificCause().getMessage();
            String duplicateField = "unknown field";

            // Extract the DB key from the message
            int keyIndex = dbMessage.indexOf("for key '");
            if (keyIndex != -1) {
                String keyPart = dbMessage.substring(keyIndex + 9); // skip "for key '"
                int endIndex = keyPart.indexOf("'");
                if (endIndex != -1) {
                    duplicateField = keyPart.substring(0, endIndex);
                    // Remove table name prefix if present
                    if (duplicateField.contains(".")) {
                        duplicateField = duplicateField.substring(duplicateField.indexOf(".") + 1);
                    }
                }
            }

            // Map DB key names to friendly column names
            Map<String, String> keyFriendlyMap = Map.of(
                    "UK893geq5bxk3o6gh642gh6cyic", "ID number",
                    "UKgnqwbwwcn7x0m5jlt4158dass", "Email",
                    "UKcf0gmg94pw4y0ic2m7vg09kv2", "Cellphone"
            );

            String message = "Duplicate entry for " +
                    keyFriendlyMap.getOrDefault(duplicateField, duplicateField) +
                    ". Please use a different value.";

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("success", false, "message", message));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "message", "Error creating admin: " + e.getMessage()));
        }
    }
    // Read an admin by ID (protected - ADMIN only)
    @GetMapping("/read/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> read(@PathVariable Integer id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("👤 Admin accessing data: " + auth.getName());

        Admin admin = adminService.read(id);
        if (admin == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok(admin);
    }

    // Update an admin (protected - ADMIN only)
    @PutMapping("/update")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> update(@RequestBody Admin admin) {
        Admin updated = adminService.update(admin);
        if (updated == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok(updated);
    }

    // Get all admins (protected - ADMIN only)
    @GetMapping("/getAll")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAll() {
        List<Admin> admins = adminService.getAllAdmins();
        return ResponseEntity.ok(admins);
    }

    // Login endpoint (public - no token required)
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, Object> loginRequest) {
        try {
            System.out.println("🔍 ADMIN LOGIN ATTEMPT: " + loginRequest);

            // Extract email and password from the request
            String email = null;
            String password = null;

            if (loginRequest.get("contact") instanceof Map) {
                Map<?, ?> contact = (Map<?, ?>) loginRequest.get("contact");
                email = (String) contact.get("email");
            } else if (loginRequest.get("email") != null) {
                email = (String) loginRequest.get("email");
            }

            password = (String) loginRequest.get("password");

            if (email == null || password == null) {
                System.out.println("❌ ADMIN LOGIN: Missing email or password");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of(
                                "success", false,
                                "message", "Email and password are required",
                                "status", "error"
                        ));
            }

            System.out.println("🔐 ADMIN LOGIN: Validating credentials for: " + email);

            AdminService.LoginResult result = adminService.validateLogin(email, password);

            if (result.isSuccess()) {
                Admin admin = result.getAdmin();

                // Generate token using TokenUtil
                String token = tokenUtil.generateToken(
                        admin.getContact().getEmail(),
                        "ROLE_ADMIN",
                        admin.getUserId(),
                        "ADMIN"
                );

                // Create response with token and user data
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("token", token);
                response.put("user", admin);
                response.put("role", "ROLE_ADMIN");
                response.put("message", "Login successful");
                response.put("status", "success");

                System.out.println("✅ ADMIN LOGIN SUCCESS: Token generated for: " + admin.getContact().getEmail());
                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> response = new HashMap<>();
                response.put("success", false);
                response.put("message", result.getMessage());
                response.put("status", "error");

                if (result.getRemainingLockTime() > 0) {
                    response.put("locked", true);
                    response.put("remainingLockTime", result.getRemainingLockTime());
                } else {
                    response.put("remainingAttempts", result.getRemainingAttempts());
                }

                System.out.println("❌ ADMIN LOGIN FAILED: " + response);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
        } catch (Exception e) {
            System.out.println("💥 ADMIN LOGIN ERROR: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Login failed: " + e.getMessage(),
                            "status", "error"
                    ));
        }
    }

    // Admin dashboard data (protected - ADMIN only)
    @GetMapping("/all-data")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllData() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("📊 Admin dashboard accessed by: " + auth.getName());

        Map<String, Object> allData = new HashMap<>();
        allData.put("applicants", adminService.getAllApplicants());
        allData.put("admins", adminService.getAllAdmins());
        allData.put("bookings", adminService.getBookings());
        allData.put("payments", adminService.getPayments());
        allData.put("registrations", adminService.getRegistration());
        allData.put("testAppointments", adminService.getTestAppointments());
        allData.put("vehicleDiscs", adminService.getVehicleDiscs());
        allData.put("vehicles", adminService.getVehicles());
        allData.put("tickets", adminService.getTickets());

        return ResponseEntity.ok(allData);
    }

    // Update applicant status (protected - ADMIN only)
    @PutMapping("/update-status/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateApplicantStatus(@PathVariable Integer id,
                                                   @RequestBody Map<String, String> request) {
        String status = request.get("status");
        String reason = request.get("reason");

        if (status == null) {
            return new ResponseEntity<>("Status is required", HttpStatus.BAD_REQUEST);
        }

        try {
            Applicant updated = adminService.updateApplicantStatus(id, status, reason);
            if (updated != null) {
                return ResponseEntity.ok(updated);
            } else {
                return new ResponseEntity<>("Applicant not found", HttpStatus.NOT_FOUND);
            }
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    // Update test result (protected - ADMIN only)
    @PutMapping("/test-appointments/update-result/{testAppointmentId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateTestResult(@PathVariable Long testAppointmentId,
                                              @RequestBody Map<String, Object> request) {
        Boolean testResult = (Boolean) request.get("testResult");
        String notes = (String) request.get("notes");

        if (testResult == null) {
            return new ResponseEntity<>("Test result is required", HttpStatus.BAD_REQUEST);
        }

        try {
            TestAppointment updated = adminService.updateTestResult(testAppointmentId, testResult, notes);
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }

    // Delete operations (protected - ADMIN only)
    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteAdmin(@PathVariable Integer id) {
        boolean deleted = adminService.deleteAdmin(id);
        if (deleted) {
            return ResponseEntity.ok("Admin deleted successfully");
        }
        return new ResponseEntity<>("Admin not found", HttpStatus.NOT_FOUND);
    }

    @DeleteMapping("/applicants/delete/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteApplicant(@PathVariable Integer id) {
        boolean deleted = adminService.deleteApplicant(id);
        if (deleted) {
            return ResponseEntity.ok("Applicant deleted successfully");
        }
        return new ResponseEntity<>("Applicant not found", HttpStatus.NOT_FOUND);
    }

    // Check roles endpoint
    @GetMapping("/check-roles")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> checkRoles() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("username", auth.getName());
        response.put("authorities", auth.getAuthorities().toString());
        response.put("isAuthenticated", auth.isAuthenticated());
        response.put("hasRoleApplicant", auth.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_APPLICANT")));
        response.put("hasRoleAdmin", auth.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN")));

        System.out.println("🔐 ADMIN ROLE CHECK: " + response);
        return ResponseEntity.ok(response);
    }

    // Validate token endpoint (public)
    @GetMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("valid", false, "message", "Authorization header missing or invalid"));
            }

            String token = authHeader.substring(7);
            if (tokenUtil.validateToken(token)) {
                Map<String, Object> response = new HashMap<>();
                response.put("valid", true);
                response.put("username", tokenUtil.extractUsername(token));
                response.put("role", tokenUtil.extractRole(token));
                response.put("userId", tokenUtil.extractUserId(token));
                response.put("userType", tokenUtil.extractUserType(token));
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("valid", false, "message", "Invalid token"));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("valid", false, "message", "Error validating token: " + e.getMessage()));
        }
    }

    // Test Token endpoint (public)
    @GetMapping("/test-token")
    public ResponseEntity<?> testToken() {
        try {
            String testToken = tokenUtil.generateToken("test@admin.co.za", "ROLE_ADMIN", 999, "ADMIN");

            Map<String, Object> response = new HashMap<>();
            response.put("token", testToken);
            response.put("valid", tokenUtil.validateToken(testToken));
            response.put("username", tokenUtil.extractUsername(testToken));
            response.put("role", tokenUtil.extractRole(testToken));
            response.put("userId", tokenUtil.extractUserId(testToken));
            response.put("userType", tokenUtil.extractUserType(testToken));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Token test failed: " + e.getMessage()));
        }
    }

    // Add this endpoint to AdminController class
    @PutMapping("/change-password")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> passwordRequest) {
        try {
            System.out.println("🔐 ADMIN CHANGE PASSWORD REQUEST: " + passwordRequest);

            String currentPassword = passwordRequest.get("currentPassword");
            String newPassword = passwordRequest.get("newPassword");

            if (currentPassword == null || newPassword == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "message", "Current password and new password are required"
                ));
            }

            if (newPassword.length() < 6) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "message", "New password must be at least 6 characters long"
                ));
            }

            // Get current admin ID from security context
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String username = auth.getName();

            // Find admin by email to get ID
            Admin admin = adminService.getAllAdmins().stream()
                    .filter(a -> a.getContact() != null &&
                            a.getContact().getEmail().equalsIgnoreCase(username))
                    .findFirst()
                    .orElse(null);

            if (admin == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of(
                        "success", false,
                        "message", "Admin not found"
                ));
            }

            boolean passwordChanged = adminService.changePassword(admin.getUserId(), currentPassword, newPassword);

            if (passwordChanged) {
                return ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Password changed successfully"
                ));
            } else {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "message", "Current password is incorrect"
                ));
            }

        } catch (Exception e) {
            System.out.println("💥 ADMIN CHANGE PASSWORD ERROR: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error changing password: " + e.getMessage()
            ));
        }
    }
    // Add these methods to AdminService class

    // Verify email for password reset
    public Map<String, Object> verifyAdminEmailForPasswordReset(String email) {
        try {
            System.out.println("🔍 ADMIN SERVICE: Verifying email for password reset: " + email);

            boolean emailExists = adminRepository.existsByEmail(email);

            if (!emailExists) {
                return Map.of(
                        "success", false,
                        "message", "Admin email not found in our system"
                );
            }

            // Generate verification code (in real app, send via email)
            String verificationCode = generateVerificationCode();
            System.out.println("📧 Verification code for admin " + email + ": " + verificationCode);

            return Map.of(
                    "success", true,
                    "message", "Verification code sent to your email",
                    "demoCode", verificationCode // Remove in production
            );

        } catch (Exception e) {
            System.out.println("❌ ADMIN SERVICE: Error verifying email: " + e.getMessage());
            return Map.of(
                    "success", false,
                    "message", "Error verifying email: " + e.getMessage()
            );
        }
    }

    // Reset admin password with verification
    public Map<String, Object> resetAdminPassword(String email, String newPassword) {
        try {
            System.out.println("🔐 ADMIN SERVICE: Resetting password for: " + email);

            Optional<Admin> adminOpt = adminRepository.findByEmail(email);
            if (!adminOpt.isPresent()) {
                return Map.of(
                        "success", false,
                        "message", "Admin not found with email: " + email
                );
            }

            Admin admin = adminOpt.get();

            // Validate new password
            if (newPassword == null || newPassword.trim().isEmpty()) {
                return Map.of(
                        "success", false,
                        "message", "New password cannot be empty"
                );
            }

            if (newPassword.length() < 6) {
                return Map.of(
                        "success", false,
                        "message", "New password must be at least 6 characters long"
                );
            }

            // Encode and set new password
            admin.setPassword(bCryptPasswordEncoder.encode(newPassword));
            adminRepository.save(admin);

            System.out.println("✅ ADMIN SERVICE: Password reset successfully for: " + email);
            return Map.of(
                    "success", true,
                    "message", "Password reset successfully"
            );

        } catch (Exception e) {
            System.out.println("❌ ADMIN SERVICE: Error resetting password: " + e.getMessage());
            return Map.of(
                    "success", false,
                    "message", "Error resetting password: " + e.getMessage()
            );
        }
    }

    private String generateVerificationCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000);
        return String.valueOf(code);
    }
}