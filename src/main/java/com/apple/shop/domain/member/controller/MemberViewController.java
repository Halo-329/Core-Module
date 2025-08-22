package com.apple.shop.domain.member.controller;

import com.apple.shop.domain.member.entity.Member;
import com.apple.shop.domain.member.repo.MemberRepo;
import com.apple.shop.domain.member.service.MemberService;
import com.apple.shop.domain.member.service.MyUserDetailsService;
import com.apple.shop.global.util.JwtUtil;
import com.apple.shop.view.ViewPath;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@Controller
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberViewController {

    private final MemberService memberService;
    private final MemberRepo memberRepo;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @GetMapping("/signup")
    String signup() { return ViewPath.MEMBER_SIGNUP; }

    @PostMapping("/add")
    String add(String usrID, String password, String usrName, String email, Model model) {
        boolean ok = memberService.SavaMember(usrID, password, usrName, email, model);
        return ok ? ViewPath.REDIRECT_ITEM_LIST : ViewPath.MEMBER_SIGNUP;
    }

    @GetMapping("/login")
    String loginPage() { return ViewPath.MEMBER_LOGIN; }

    @PostMapping("/login/jwt")
    String loginJWT(@RequestParam String username,
                    @RequestParam String password,
                    HttpServletResponse response,
                    Model model) {
        var token = new UsernamePasswordAuthenticationToken(username, password);
        try {
            var auth = authenticationManagerBuilder.getObject().authenticate(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
            String jwt = JwtUtil.createToken(auth);
            Cookie cookie = new Cookie("jwt", jwt);
            cookie.setPath("/");
            cookie.setMaxAge(24 * 60 * 60);
            cookie.setHttpOnly(true);
            response.addCookie(cookie);
            return "redirect:/item/list";
        } catch (Exception e) {
            model.addAttribute("loginError", "아이디 또는 비밀번호가 잘못되었습니다.");
            return ViewPath.MEMBER_LOGIN;
        }
    }

    @PostMapping("/logout")
    String logout() { return ViewPath.REDIRECT_ITEM_LIST; }

    @PostMapping("/logout/jwt")
    String jwtLogout(HttpServletResponse response){
        Cookie cookie = new Cookie("jwt", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);
        return ViewPath.REDIRECT_ITEM_LIST;
    }

    @GetMapping("/profile")
    String me(Authentication auth, Model model) {
        String id = auth.getName();
        Optional<Member> opt = memberRepo.findFirstByLoginId(id);
        MyUserDetailsService.CustomUser result =  (MyUserDetailsService.CustomUser) auth.getPrincipal();

        if (opt.isPresent()) {
            model.addAttribute("member", opt.get());
            return ViewPath.MEMBER_PROFILE;
        }

        return "member/login";
    }

    @GetMapping("/register")
    String register() { return ViewPath.MEMBER_PROFILE; }
}
