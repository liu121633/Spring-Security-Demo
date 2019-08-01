package org.lhj.doman.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author 刘洪君
 * @date 2019/8/1 20:57
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UrlEntity {
    String uri;
    String httpMethod;
}
