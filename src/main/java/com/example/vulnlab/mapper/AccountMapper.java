package com.example.vulnlab.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.vulnlab.entity.Account;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AccountMapper extends BaseMapper<Account> {
}
