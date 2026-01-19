package za.ac.cput.Controller.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import za.ac.cput.Domain.User.Applicant;
import za.ac.cput.Service.impl.ApplicantService;
import za.ac.cput.Service.jwt.TokenUtil;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/applicants")
public class ApplicantController {

    private final ApplicantService applicantService;

    @Autowired
    private TokenUtil tokenUtil;

    @Autowired
    public ApplicantController(ApplicantService applicantService) {
        this.applicantService = applicantService;
    }

    // ✅ Public test endpoint
    @GetMapping("/test-public")
    public ResponseEntity<?> testPublic() {
        System.out.println("✅ TEST PUBLIC: This works without login");
        return ResponseEntity.ok(Map.of("message", "Public endpoint works!"));
    }

    // ✅ GET login page endpoint (public)
    @GetMapping("/login")
    public ResponseEntity<?> loginPage() {
        System.out.println("🔍 APPLICANT LOGIN PAGE: Login page accessed");
        return ResponseEntity.ok(Map.of(
                "message", "Applicant login page - use POST /applicants/login with email and password to authenticate",
                "required_fields", "email, password",
                "example", Map.of("email", "user@example.com", "password", "yourpassword")
        ));
    }

    // ✅ Protected test endpoint - FIXED: Added @PreAuthorize
    @GetMapping("/test-protected")
    @PreAuthorize("hasAnyRole('APPLICANT', 'ADMIN')")
    public ResponseEntity<?> testProtected() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("🛡️ TEST PROTECTED: User " + auth.getName() + " with roles: " + auth.getAuthorities());

        return ResponseEntity.ok(Map.of(
                "message", "Protected endpoint works!",
                "user", auth.getName(),
                "roles", auth.getAuthorities().toString(),
                "authenticated", auth.isAuthenticated()
        ));
    }

    // ✅ Check roles endpoint - FIXED: Added @PreAuthorize
    @GetMapping("/check-roles")
    @PreAuthorize("hasAnyRole('APPLICANT', 'ADMIN')")
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

        System.out.println("🔐 ROLE CHECK: " + response);
        return ResponseEntity.ok(response);
    }

    // Create a new applicant (public - no token required)
    @PostMapping("/create")
    public ResponseEntity<?> create(@RequestBody Applicant applicant) {
        try {
            // --- Basic validations ---
            if (applicant.getContact() == null || applicant.getContact().getEmail() == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("success", false, "message", "Email is required"));
            }

            String email = applicant.getContact().getEmail();

            if (email.endsWith("@admin.co.za")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("success", false, "message", "Applicants cannot use admin email domain (@admin.co.za)"));
            }

            if (!email.contains("@")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of("success", false, "message", "Invalid email format for applicant"));
            }

            // --- Create the applicant ---
            Applicant created = applicantService.create(applicant);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("success", true, "data", created));

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
                    .body(Map.of("success", false, "message", "Error creating applicant: " + e.getMessage()));
        }
    }


    // Read an applicant by ID (protected)
    @GetMapping("/read/{id}")
    @PreAuthorize("hasAnyRole('APPLICANT', 'ADMIN')")
    public ResponseEntity<?> read(@PathVariable Integer id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("👤 Accessing applicant data by user: " + auth.getName());

        Applicant applicant = applicantService.read(id);
        if (applicant == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok(applicant);
    }

    // ✅ FIXED: Update an applicant - SIMPLIFIED (no path variable)
    @PutMapping("/update")
    @PreAuthorize("hasAnyRole('APPLICANT', 'ADMIN')")
    public ResponseEntity<?> update(@RequestBody Applicant applicant) {
        System.out.println("🔧 UPDATE APPLICANT: Updating user ID: " + applicant.getUserId());

        Applicant updated = applicantService.update(applicant);
        if (updated == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok(updated);
    }

    // Get all applicants (protected - ADMIN only)
    @GetMapping("/getAll")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAll() {
        List<Applicant> applicants = applicantService.getAll();
        return ResponseEntity.ok(applicants);
    }

    // Login endpoint (public - no token required)
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, Object> loginRequest) {
        try {
            System.out.println("🔍 APPLICANT LOGIN ATTEMPT: " + loginRequest);

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
                System.out.println("❌ APPLICANT LOGIN: Missing email or password");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(Map.of(
                                "success", false,
                                "message", "Email and password are required",
                                "status", "error"
                        ));
            }

            System.out.println("🔐 APPLICANT LOGIN: Validating credentials for: " + email);

            ApplicantService.LoginResult result = applicantService.validateLogin(email, password);

            if (result.isSuccess()) {
                Applicant applicant = result.getApplicant();

                // Generate token using TokenUtil
                String token = tokenUtil.generateToken(
                        applicant.getContact().getEmail(),
                        "ROLE_APPLICANT",
                        applicant.getUserId(),
                        "APPLICANT"
                );

                // Create response with token and user data
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("token", token);
                response.put("user", applicant);
                response.put("role", "ROLE_APPLICANT");
                response.put("message", "Login successful");
                response.put("status", "success");

                System.out.println("✅ APPLICANT LOGIN SUCCESS: Token generated for: " + applicant.getContact().getEmail());
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

                System.out.println("❌ APPLICANT LOGIN FAILED: " + response);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
        } catch (Exception e) {
            System.out.println("💥 APPLICANT LOGIN ERROR: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "success", false,
                            "message", "Login failed: " + e.getMessage(),
                            "status", "error"
                    ));
        }
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
            String testToken = tokenUtil.generateToken("test@applicant.com", "ROLE_APPLICANT", 888, "APPLICANT");

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

    // Get applicant by ID (alternative endpoint)
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('APPLICANT', 'ADMIN')")
    public ResponseEntity<?> getApplicantById(@PathVariable Integer id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("👤 Getting applicant by ID: " + id + " requested by: " + auth.getName());

        Applicant applicant = applicantService.read(id);
        if (applicant == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok(applicant);
    }

    // Delete applicant (ADMIN only)
    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> delete(@PathVariable Integer id) {
        boolean deleted = applicantService.delete(id);
        if (deleted) {
            return ResponseEntity.ok(Map.of("message", "Applicant deleted successfully"));
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }
    // Add these endpoints to ApplicantController class

    // Verify applicant email for password reset
    @PostMapping("/verify-email-password-reset")
    public ResponseEntity<?> verifyEmailForPasswordReset(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");

            if (email == null || email.trim().isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "message", "Email is required"
                ));
            }

            Map<String, Object> result = applicantService.verifyApplicantEmailForPasswordReset(email);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            System.out.println("💥 APPLICANT CONTROLLER ERROR: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error verifying email: " + e.getMessage()
            ));
        }
    }

    // Reset applicant password
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        try {
            String email = request.get("email");
            String newPassword = request.get("newPassword");

            if (email == null || newPassword == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "message", "Email and new password are required"
                ));
            }

            Map<String, Object> result = applicantService.resetApplicantPassword(email, newPassword);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            System.out.println("💥 APPLICANT CONTROLLER ERROR: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error resetting password: " + e.getMessage()
            ));
        }
    }

    // Change password (requires current password - for logged-in users)
    @PutMapping("/change-password")
    @PreAuthorize("hasAnyRole('APPLICANT', 'ADMIN')")
    public ResponseEntity<?> changePassword(@RequestBody Map<String, String> passwordRequest) {
        try {
            String currentPassword = passwordRequest.get("currentPassword");
            String newPassword = passwordRequest.get("newPassword");

            if (currentPassword == null || newPassword == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "success", false,
                        "message", "Current password and new password are required"
                ));
            }

            // Get current user from security context
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String email = auth.getName();

            boolean passwordChanged = applicantService.changeApplicantPassword(email, currentPassword, newPassword);

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
            System.out.println("💥 APPLICANT CONTROLLER ERROR: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "success", false,
                    "message", "Error changing password: " + e.getMessage()
            ));
        }
    }



}