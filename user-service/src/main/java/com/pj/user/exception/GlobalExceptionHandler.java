package com.pj.user.exception;

import com.pj.user.dto.UserResponse;
import com.pj.user.security.AuthorizationServerConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<UserResponse> handleGeneralException(Exception ex, WebRequest request) {
        log.error("GlobalExceptionHandler caught unexpected error for request {}:", request.getDescription(false), ex);
        UserResponse response = new UserResponse();
        response.setSuccess(false);
        response.setErrorMsg("An unexpected error occurred: " + ex.getLocalizedMessage());
        response.setErrorCode(50001);
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<UserResponse> handleUserAlreadyExistsException(UserAlreadyExistsException ex, WebRequest request) {
        log.error("GlobalExceptionHandler caught unexpected error for request {}:", request.getDescription(false), ex);
        UserResponse response = new UserResponse();
        response.setSuccess(false);
        response.setErrorMsg(ex.getLocalizedMessage());
        response.setErrorCode(50002);
        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<UserResponse> handleInvalidCredentialsException(InvalidCredentialsException ex, WebRequest request) {
        log.error("GlobalExceptionHandler caught unexpected error for request {}:", request.getDescription(false), ex);
        UserResponse response = new UserResponse();
        response.setSuccess(false);
        response.setErrorMsg(ex.getLocalizedMessage());
        response.setErrorCode(50003);
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<UserResponse> handleUserNotFoundException(UserNotFoundException ex, WebRequest request) {
        UserResponse response = new UserResponse();
        response.setSuccess(false);
        response.setErrorMsg(ex.getLocalizedMessage());
        response.setErrorCode(50004); // Not Found
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }
}
