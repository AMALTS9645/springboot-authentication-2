 //code-start

package com.example.loginapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import javax.validation.constraints.*;
import javax.validation.BindingResult;
import javax.validation.constraints.NotEmpty;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.http.HttpMethod;

@SpringBootApplication
public class LoginApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginApiApplication.class, args);
    }

    // Security: Use HTTPS for API endpoints
    @CrossOrigin(origins = "*")
    @RestController
    @RequestMapping("/api")
    public class LoginController {

        private final LoginService loginService;

        public LoginController(LoginService loginService) {
            this.loginService = loginService;
        }

        @PostMapping(value = "/login", consumes = "application/json")
        public ResponseEntity<?> loginUser(@Valid @RequestBody LoginDto loginDto, BindingResult bindingResult) {
            if (bindingResult.hasErrors()) {
                return new ResponseEntity<>(bindingResult.getAllErrors(), HttpStatus.BAD_REQUEST);
            }

            try {
                User user = loginService.loginUser(loginDto.getUsername(), loginDto.getPassword());
                return ResponseEntity.ok(user);
            } catch (UserNotFoundException e) {
                return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
            }
        }

        @ExceptionHandler(UserNotFoundException.class)
        public ResponseEntity<?> handleUserNotFoundException(UserNotFoundException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }

    // Security: Use secure hashing for passwords
    @Service
    public class LoginService {

        // Security: Password should be stored as hash
        private final UserRepository userRepository;

        public LoginService(UserRepository userRepository) {
            this.userRepository = userRepository;
        }

        public User loginUser(String username, String password) throws UserNotFoundException {
            Optional<User> userOpt = userRepository.findByUsername(username);

            userOpt.ifPresent(user -> {
                if (user.getPassword().equals(Hashing.sha256().hashString(password, StandardCharsets.UTF_8).toString())) {
                    return user;
                } else {
                    throw new UserNotAuthorizedException("Invalid password");
                }
            });

            throw new UserNotFoundException("User not found");
        }
    }

    // Security: Exception handling with proper logging
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public static class UserNotFoundException extends RuntimeException {
        public UserNotFoundException(String message) {
            super(message);
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static class UserNotAuthorizedException extends RuntimeException {
        public UserNotAuthorizedException(String message) {
            super(message);
        }
    }

    // Security: UserRepository should not expose sensitive information
    @Repository
    public interface UserRepository {
        Optional<User> findByUsername(String username);
    }

    // Security: DTO should not contain sensitive information
    public class LoginDto {

        @NotEmpty(message = "Username is required")
        private String username;

        @NotEmpty(message = "Password is required")
        private String password;

        // Getters and setters
    }

    // Security: User should not be serializable
    public class User {

        private String username;
        private String password;

        // Getters and setters
    }

//code-end

package com.example.loginapi.repository;

import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, String> {

    Optional<User> findByUsername(String username);
}

//code-end