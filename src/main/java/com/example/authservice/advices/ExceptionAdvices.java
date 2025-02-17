package com.example.authservice.advices;

import com.example.authservice.dtos.ResponseDto;
import com.example.authservice.dtos.ResponseStatus;
import com.example.authservice.exceptions.UserSignUpErrorException;
import com.example.authservice.exceptions.UserUnAuthorizedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionAdvices {


    @ExceptionHandler(UserSignUpErrorException.class)
    public ResponseEntity<ResponseDto<Object>> handleUserSignUpErrorException(UserSignUpErrorException e) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ResponseDto<>(
                        ResponseStatus.FAILURE,
                        e.getMessage(),
                        null)
                );
    }
    @ExceptionHandler(UserUnAuthorizedException.class)
    public ResponseEntity<ResponseDto<Object>> handleUserUnAuthorizedException(UserUnAuthorizedException e) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new ResponseDto<>(
                        ResponseStatus.FAILURE,
                        e.getMessage(),
                        null)
                );
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ResponseDto<Object>> handleRuntimeException(RuntimeException e) {
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ResponseDto<>(
                        ResponseStatus.FAILURE,
                        e.getMessage(),
                        null)
                );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseDto<Object>> handleException(Exception e) {
       return ResponseEntity
               .status(HttpStatus.INTERNAL_SERVER_ERROR)
               .body(new ResponseDto<>(
                       ResponseStatus.FAILURE,
                       e.getMessage(),
                       null)
               );
    }
}
