package com.example.authservice.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResponseDto<T> {
    private ResponseStatus status;
    private String message;
    private T data;

    public ResponseDto(){}
    public ResponseDto(ResponseStatus status, String message, T data){
        this.status = status;
        this.message = message;
        this.data = data;
    }
}
