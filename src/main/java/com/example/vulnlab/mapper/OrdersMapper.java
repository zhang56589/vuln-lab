package com.example.vulnlab.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.vulnlab.entity.Orders;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface OrdersMapper extends BaseMapper<Orders> {
}
