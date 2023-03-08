package com.springboot.usermanagement.converter;

import java.util.Map;

import com.springboot.usermanagement.dto.UserManagementDto;
import com.springboot.usermanagement.entity.UserManagementEntity;

public interface EntityDtoconverter <E extends UserManagementEntity, D extends UserManagementDto> {
	E convertToEntity(D dto, Map<String, Object>propertyMap);
	D convertToDto(E entity, Map<String,Object>propertyMap);

}
