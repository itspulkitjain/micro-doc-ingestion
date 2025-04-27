package com.pj.user.dto;

import com.pj.user.entity.UserEntity;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import java.time.ZonedDateTime;

@Mapper(imports = {ZonedDateTime.class})
public interface UserMapper  {

    public UserMapper mapper = Mappers.getMapper(UserMapper.class);

    @Mapping(target = "password", ignore = true)
    UserEntity toEntity(UserRequest userRequest);

    @Mapping(target = "password", ignore = true)
    User toJson(UserEntity user);
}
