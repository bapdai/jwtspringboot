package jwt.example.jwtspringboot.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginRequest {
    private String username;
    private String password;

    /*
    * Create an empty loginRequest object
    * */
    public LoginRequest(){
        super();
    }
    /*
    * Create a LoginRequest object with full attributes
    *
    * @param username user's user name
    * @param password
    * */
    public LoginRequest(String username, String password){
        super();
        this.username=username;
        this.password=password;
    }
}
