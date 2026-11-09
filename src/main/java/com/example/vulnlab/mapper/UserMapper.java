package com.example.vulnlab.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.vulnlab.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {
}
