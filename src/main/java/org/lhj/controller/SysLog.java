package org.lhj.controller;

import lombok.Getter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author 刘洪君
 * @date 2019/8/1 21:46
 */
@RestController
@RequestMapping("/log")
public class SysLog {
    @GetMapping
    public String all() {
        return "all";
    }

}
