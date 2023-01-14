/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.server.security.jwt;

import com.google.common.collect.ImmutableSet;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.SigningKeyResolver;
import io.trino.server.security.AbstractBearerAuthenticator;
import io.trino.server.security.AuthenticationException;
import io.trino.server.security.UserMapping;
import io.trino.server.security.UserMappingException;
import io.trino.spi.security.BasicPrincipal;
import io.trino.spi.security.Identity;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;

import java.util.List;
import java.util.Optional;

import static io.trino.server.security.UserMapping.createUserMapping;
import static io.trino.server.security.jwt.JwtUtil.newJwtParserBuilder;
import static java.util.Objects.requireNonNull;

public class JwtAuthenticator
        extends AbstractBearerAuthenticator
{
    private final JwtParser jwtParser;
    private final String principalField;
    private final UserMapping userMapping;
    private final Optional<String> groupsField;

    @Inject
    public JwtAuthenticator(JwtAuthenticatorConfig config, @ForJwt SigningKeyResolver signingKeyResolver)
    {
        principalField = config.getPrincipalField();

        JwtParserBuilder jwtParser = newJwtParserBuilder()
                .setSigningKeyResolver(signingKeyResolver);

        if (config.getRequiredIssuer() != null) {
            jwtParser.requireIssuer(config.getRequiredIssuer());
        }

        if (config.getRequiredAudience() != null) {
            jwtParser.requireAudience(config.getRequiredAudience());
        }
        this.jwtParser = jwtParser.build();

        groupsField = requireNonNull(config.getGroupsField(), "groupsField is null");
        userMapping = createUserMapping(config.getUserMappingPattern(), config.getUserMappingFile());
    }

    @Override
    protected Optional<Identity> createIdentity(String token)
            throws UserMappingException
    {
        Claims claims = jwtParser.parseClaimsJws(token)
                .getBody();
        Optional<String> principal = Optional.ofNullable(claims.get(principalField, String.class));
        if (principal.isEmpty()) {
            return Optional.empty();
        }
        Identity.Builder builder = Identity.forUser(userMapping.mapUser(principal.get()));
        builder.withPrincipal(new BasicPrincipal(principal.get()));
        groupsField.flatMap(field -> Optional.ofNullable((List<String>) claims.get(field)))
                .ifPresent(groups -> builder.withGroups(ImmutableSet.copyOf(groups)));
        return Optional.of(builder.build());
    }

    @Override
    protected AuthenticationException needAuthentication(ContainerRequestContext request, Optional<String> currentToken, String message)
    {
        return new AuthenticationException(message, "Bearer realm=\"Trino\", token_type=\"JWT\"");
    }
}
