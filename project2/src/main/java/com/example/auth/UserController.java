package com.example.auth;

import com.example.auth.domain.User;
import com.example.auth.domain.UserRepository;
import com.example.auth.jwt.JwtToken;
import com.example.auth.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
//import java.util.Collections;
import java.util.*;

@RequiredArgsConstructor
@Controller
public class UserController {

    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;
    private JwtToken jwtToken;
    private Logger logger = LoggerFactory.getLogger(UserController.class);


    // 회원가입
    @PostMapping("/add")
    public String join(@RequestParam("id")String id, @RequestParam("password")String password, @RequestParam("auth")String auth){//(@RequestBody Map<String, String> user) {
        userRepository.save(User.builder()
                .email(id)//(user.get("email"))
                .password(passwordEncoder.encode(password))
                .roles(Collections.singletonList(auth))
                .build()).getId();
        return "index"; // 로그인으로 이동
    }

    @GetMapping("/signup")
    public String signup(Model model){
        return "/signup";
    }

    // 로그인
    @PostMapping("/login")
    public String login(HttpServletRequest request, HttpServletResponse response, Model model) {//(@RequestParam("username")String username, @RequestParam("password")String password, HttpServletResponse response){ //(@RequestBody Map<String, String> user) {
        String username=request.getParameter("username");
        String password=request.getParameter("password");
        User member = userRepository.findByEmail(username)
                .orElseThrow(() -> new IllegalArgumentException("Not registered"));
        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new IllegalArgumentException("Wrong password");
        }
        jwtToken=new JwtToken(jwtTokenProvider.createToken(member.getUsername(), member.getRoles())); // return
//        System.out.println("controller: "+jwtToken.token);
        logger.info(jwtToken.token);
        model.addAttribute("token", jwtToken.token);
        return "/temp";
    }


    @RequestMapping("/user/main")
    public String usermain(){
//        System.out.println("usermain");
        logger.info("usermain");
        return "/user/main";
    }

//    @RequestMapping("/temp")
//    public ResponseEntity<?> temp(Model model){
//        System.out.println("temp");
////        model.addAttribute("token", jwtToken.token);
//
////        return "/user/main";
//        return ResponseEntity.ok(jwtToken);
//    }

    @RequestMapping("/")
    public String index(Model model){
        return "index";
    }

}
