package com.apple.shop.domain.cart.controller;

import com.apple.shop.view.ViewPath;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@Controller
@RequestMapping("/cart")
public class CartController {

    // http://localhost:8080/cart
    @GetMapping
    String cartView(){
        return ViewPath.CART_VIEW;
    }

    @PostMapping
    String addToCart(){
        return "";
    }
}
