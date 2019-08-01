package org.lhj.doman.model;

import lombok.Data;

import javax.validation.constraints.NotBlank;

/**
 * @author 刘洪君
 * @date 2019/8/1 18:01
 */
@Data
public class UserAuthModel {
    @NotBlank
    String username;
    @NotBlank
    String password;
}
